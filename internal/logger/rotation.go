package logger

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go-proxy-guard/internal/config"
)

// rotationManager управляет ротацией логов
type rotationManager struct {
	filename      string
	maxSizeMB     int
	maxAgeDays    int
	maxBackups    int
	compress      bool
	lastCheck     time.Time
	checkInterval time.Duration
	mu            sync.Mutex
}

func newRotationManager(filename string, cfg config.RotationConfig) (*rotationManager, error) {
	return &rotationManager{
		filename:      filename,
		maxSizeMB:     cfg.MaxSizeMB,
		maxAgeDays:    cfg.MaxAgeDays,
		maxBackups:    cfg.MaxBackups,
		compress:      cfg.Compress,
		lastCheck:     time.Now(),
		checkInterval: time.Minute, // Проверяем раз в минуту
	}, nil
}

// checkAndRotate проверяет необходимость ротации и выполняет её
func (rm *rotationManager) checkAndRotate() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Проверяем не слишком ли часто
	if time.Since(rm.lastCheck) < rm.checkInterval {
		return nil
	}
	rm.lastCheck = time.Now()

	// Проверяем размер файла
	info, err := os.Stat(rm.filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Файл еще не создан
		}
		return fmt.Errorf("ошибка получения информации о файле: %w", err)
	}

	maxSizeBytes := int64(rm.maxSizeMB) * 1024 * 1024
	if info.Size() < maxSizeBytes {
		// Проверяем только старые файлы
		return rm.cleanOldFiles()
	}

	// Выполняем ротацию
	return rm.rotate()
}

// rotate выполняет ротацию текущего файла
func (rm *rotationManager) rotate() error {
	// Генерируем имя для ротированного файла
	timestamp := time.Now().Format("20060102-150405")
	rotatedName := rm.filename + "." + timestamp

	// Переименовываем текущий файл
	if err := os.Rename(rm.filename, rotatedName); err != nil {
		return fmt.Errorf("ошибка переименования файла: %w", err)
	}

	// Сжимаем, если нужно
	if rm.compress {
		if err := rm.compressFile(rotatedName); err != nil {
			// Если сжатие не удалось, оставляем файл несжатым
			fmt.Fprintf(os.Stderr, "Ошибка сжатия файла лога: %v\n", err)
		}
	}

	// Очищаем старые файлы
	return rm.cleanOldFiles()
}

// compressFile сжимает файл с помощью gzip
func (rm *rotationManager) compressFile(filename string) error {
	// Открываем исходный файл
	src, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("ошибка открытия файла для сжатия: %w", err)
	}
	defer src.Close()

	// Создаем файл для сжатых данных
	dst, err := os.Create(filename + ".gz")
	if err != nil {
		return fmt.Errorf("ошибка создания файла для сжатия: %w", err)
	}
	defer dst.Close()

	// Создаем gzip writer
	gzWriter := gzip.NewWriter(dst)
	defer gzWriter.Close()

	// Копируем данные
	if _, err := io.Copy(gzWriter, src); err != nil {
		return fmt.Errorf("ошибка сжатия данных: %w", err)
	}

	// Удаляем исходный файл
	if err := os.Remove(filename); err != nil {
		return fmt.Errorf("ошибка удаления исходного файла: %w", err)
	}

	return nil
}

// cleanOldFiles удаляет старые файлы логов
func (rm *rotationManager) cleanOldFiles() error {
	dir := filepath.Dir(rm.filename)
	baseName := filepath.Base(rm.filename)

	// Читаем все файлы в директории
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("ошибка чтения директории: %w", err)
	}

	var logFiles []logFileInfo
	cutoffTime := time.Now().AddDate(0, 0, -rm.maxAgeDays)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Проверяем, что это файл лога (основной или ротированный)
		if !strings.HasPrefix(name, baseName) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Проверяем возраст файла
		if info.ModTime().Before(cutoffTime) {
			// Удаляем старый файл
			fullPath := filepath.Join(dir, name)
			if err := os.Remove(fullPath); err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка удаления старого файла лога %s: %v\n", fullPath, err)
			}
			continue
		}

		// Добавляем в список для проверки количества бэкапов
		if name != baseName {
			logFiles = append(logFiles, logFileInfo{
				path:    filepath.Join(dir, name),
				modTime: info.ModTime(),
			})
		}
	}

	// Сортируем по времени модификации (старые первыми)
	sort.Slice(logFiles, func(i, j int) bool {
		return logFiles[i].modTime.Before(logFiles[j].modTime)
	})

	// Удаляем лишние файлы, если превышен лимит
	if len(logFiles) > rm.maxBackups {
		for i := 0; i < len(logFiles)-rm.maxBackups; i++ {
			if err := os.Remove(logFiles[i].path); err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка удаления файла лога %s: %v\n", logFiles[i].path, err)
			}
		}
	}

	return nil
}

type logFileInfo struct {
	path    string
	modTime time.Time
}
