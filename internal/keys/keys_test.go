package keys

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	algorithms := []Algorithm{
		AlgorithmHS256,
		AlgorithmHS512,
		AlgorithmRS256,
		AlgorithmRS512,
		AlgorithmES256,
		AlgorithmES512,
		AlgorithmEdDSA,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			key, err := GenerateKey(alg)
			if err != nil {
				t.Fatalf("Ошибка генерации ключа: %v", err)
			}

			if key.Metadata.ID == "" {
				t.Error("ID ключа не установлен")
			}

			if key.Metadata.Algorithm != alg {
				t.Errorf("Ожидался алгоритм %s, получен %s", alg, key.Metadata.Algorithm)
			}

			if key.Metadata.Status != StatusActive {
				t.Errorf("Ожидался статус %s, получен %s", StatusActive, key.Metadata.Status)
			}

			// Проверяем наличие ключа в зависимости от алгоритма
			switch alg {
			case AlgorithmHS256:
				if key.HMAC == nil || len(key.HMAC) != 32 {
					t.Errorf("HMAC ключ HS256: ожидалось 32 байта, len=%d", len(key.HMAC))
				}
			case AlgorithmHS512:
				if key.HMAC == nil || len(key.HMAC) != 64 {
					t.Errorf("HMAC ключ HS512: ожидалось 64 байта, len=%d", len(key.HMAC))
				}
			case AlgorithmRS256, AlgorithmRS512, AlgorithmES256, AlgorithmES512, AlgorithmEdDSA:
				if key.KeyPair == nil {
					t.Error("Пара ключей не сгенерирована")
				}
				if key.KeyPair.Private == nil {
					t.Error("Приватный ключ не сгенерирован")
				}
				if key.KeyPair.Public == nil {
					t.Error("Публичный ключ не сгенерирован")
				}
			}
		})
	}
}

func TestFileStore(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := NewFileStore(tmpDir)
	if err != nil {
		t.Fatalf("Ошибка создания хранилища: %v", err)
	}

	// Генерируем ключ
	key, err := store.GenerateKey(AlgorithmHS256)
	if err != nil {
		t.Fatalf("Ошибка генерации ключа: %v", err)
	}

	// Проверяем, что ключ сохранен
	if key.Metadata.ID == "" {
		t.Error("ID ключа не установлен")
	}

	// Загружаем ключ обратно
	loadedKey, err := store.GetKey(AlgorithmHS256)
	if err != nil {
		t.Fatalf("Ошибка загрузки ключа: %v", err)
	}

	if loadedKey.Metadata.ID != key.Metadata.ID {
		t.Errorf("ID ключа не совпадает: ожидался %s, получен %s", key.Metadata.ID, loadedKey.Metadata.ID)
	}

	if len(loadedKey.HMAC) != len(key.HMAC) {
		t.Error("Размер HMAC ключа не совпадает")
	}
}

func TestFileStore_RegenerateKey(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := NewFileStore(tmpDir)
	if err != nil {
		t.Fatalf("Ошибка создания хранилища: %v", err)
	}

	// Генерируем первый ключ
	key1, err := store.GenerateKey(AlgorithmHS256)
	if err != nil {
		t.Fatalf("Ошибка генерации ключа: %v", err)
	}

	// Регенерируем ключ
	key2, err := store.RegenerateKey(AlgorithmHS256)
	if err != nil {
		t.Fatalf("Ошибка регенерации ключа: %v", err)
	}

	// Проверяем, что ключи разные
	if key1.Metadata.ID == key2.Metadata.ID {
		t.Error("ID ключей совпадают после регенерации")
	}

	// Проверяем, что создана резервная копия
	backupPath := filepath.Join(tmpDir, "hs256_"+key1.Metadata.ID+".key.backup")
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("Резервная копия не создана")
	}
}

func TestEncryption(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	data := []byte("test data")

	// Шифруем
	encrypted, err := encryptData(data, masterKey)
	if err != nil {
		t.Fatalf("Ошибка шифрования: %v", err)
	}

	if len(encrypted) == 0 {
		t.Error("Зашифрованные данные пусты")
	}

	// Расшифровываем
	decrypted, err := decryptData(encrypted, masterKey)
	if err != nil {
		t.Fatalf("Ошибка расшифровки: %v", err)
	}

	// Проверяем, что данные совпадают
	if string(decrypted) != string(data) {
		t.Errorf("Расшифрованные данные не совпадают: ожидалось %s, получено %s", data, decrypted)
	}
}

func TestInitializeKeys(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := NewFileStore(tmpDir)
	if err != nil {
		t.Fatalf("Ошибка создания хранилища: %v", err)
	}

	algorithms := []string{"HS256", "HS512", "RS256", "RS512", "ES256", "ES512"}

	// Инициализируем ключи
	if err := store.InitializeKeys(algorithms); err != nil {
		t.Fatalf("Ошибка инициализации ключей: %v", err)
	}

	// Проверяем, что ключи созданы
	for _, algStr := range algorithms {
		key, err := store.GetKey(Algorithm(algStr))
		if err != nil {
			t.Errorf("Ключ для %s не найден: %v", algStr, err)
		}
		if key == nil {
			t.Errorf("Ключ для %s равен nil", algStr)
		}
	}

	snapshot := func(st *FileStore) map[string]string {
		m := make(map[string]string)
		for _, a := range algorithms {
			k, err := st.GetKey(Algorithm(a))
			if err != nil {
				t.Fatalf("%s: %v", a, err)
			}
			m[a] = k.Metadata.ID
		}
		return m
	}

	before := snapshot(store)

	store2, err := NewFileStore(tmpDir)
	if err != nil {
		t.Fatalf("повторное открытие хранилища: %v", err)
	}
	if err := store2.InitializeKeys(algorithms); err != nil {
		t.Fatalf("повторная инициализация: %v", err)
	}
	after := snapshot(store2)

	for _, a := range algorithms {
		if after[a] != before[a] {
			t.Errorf("%s: после reload ожидался тот же key ID, было %s стало %s",
				a, before[a], after[a])
		}
	}
}
