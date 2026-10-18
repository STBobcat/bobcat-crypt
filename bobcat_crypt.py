#!/usr/bin/env python3
"""
Криптер с поддержкой AES-256-CCM
Формат ссылки: bobcat://aes-256-ccm/ЗАШИФРОВАННОЕ_СОДЕРЖИМОЕ
"""

import argparse
import base64
import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Константы
SALT_SIZE = 16
NONCE_SIZE = 13  # Рекомендуемый размер для AES-CCM
TAG_SIZE = 16    # 128 бит тег аутентификации
MIN_PASSWORD_LEN = 20
ITERATIONS = 100_000  # Количество итераций PBKDF2

# Единый префикс ссылки (был рассинхрон между encrypt и decrypt)
LINK_PREFIX = "bobcat://aes-256-ccm/"


class BobcatCrypto:
    """Класс для шифрования/дешифрования в формате bobcat://"""

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Получение ключа из пароля через PBKDF2-HMAC-SHA256"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 бит для AES-256
            salt=salt,
            iterations=ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def encrypt(data: str, password: str) -> str:
        """
        Шифрование данных с AES-256-CCM
        Возвращает ссылку вида: bobcat://aes-256-ccm/ЗАШИФРОВАННОЕ
        """
        if len(password) < MIN_PASSWORD_LEN:
            raise ValueError(f"Пароль должен быть минимум {MIN_PASSWORD_LEN} символов")

        # Генерация случайной соли и nonce
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        # Получение ключа
        key = BobcatCrypto._derive_key(password, salt)

        # Шифрование
        cipher = AESCCM(key, tag_length=TAG_SIZE)
        data_bytes = data.encode('utf-8')
        ciphertext = cipher.encrypt(nonce, data_bytes, None)

        # Формирование: salt + nonce + ciphertext
        combined = salt + nonce + ciphertext

        # Кодирование в base64 URL-safe (без padding)
        encoded = base64.urlsafe_b64encode(combined).decode('ascii').rstrip('=')

        return f"{LINK_PREFIX}{encoded}"

    @staticmethod
    def decrypt(link: str, password: str) -> str:
        """
        Дешифрование данных из ссылки bobcat://
        Возвращает исходное содержимое
        """
        if len(password) < MIN_PASSWORD_LEN:
            raise ValueError(f"Пароль должен быть минимум {MIN_PASSWORD_LEN} символов")

        # Проверка формата ссылки
        if not link.startswith(LINK_PREFIX):
            raise ValueError(
                f"Неверный формат ссылки. Ожидается: {LINK_PREFIX}..."
            )

        # Извлечение закодированных данных (убираем префикс один раз)
        encoded_data = link[len(LINK_PREFIX):]

        # Восстановление padding для base64
        missing_padding = len(encoded_data) % 4
        if missing_padding:
            encoded_data += "=" * (4 - missing_padding)

        try:
            combined = base64.urlsafe_b64decode(encoded_data)
        except Exception as e:
            raise ValueError(f"Некорректная base64-строка в ссылке: {e}")

        # Проверка минимальной длины
        min_len = SALT_SIZE + NONCE_SIZE + TAG_SIZE
        if len(combined) < min_len:
            raise ValueError("Ссылка слишком короткая или повреждена")

        # Извлечение salt, nonce и ciphertext
        salt = combined[:SALT_SIZE]
        nonce = combined[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        ciphertext = combined[SALT_SIZE + NONCE_SIZE:]

        # Получение ключа
        key = BobcatCrypto._derive_key(password, salt)

        # Дешифрование
        cipher = AESCCM(key, tag_length=TAG_SIZE)
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError("Не удалось расшифровать: неверный пароль или повреждённые данные")

        return plaintext.decode('utf-8')


def main():
    parser = argparse.ArgumentParser(
        description="Криптер с AES-256-CCM и ссылками bobcat://",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  Шифрование:
    python utility.py --crypt --aes-256-ccm --password=my_very_secure_password_123 "Секретные данные"

  Дешифрование:
    python utility.py --decrypt --aes-256-ccm --password=my_very_secure_password_123 "bobcat://aes-256-ccm/..."
        """
    )

    # Группа для режима работы
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--crypt', action='store_true', help='Режим шифрования')
    mode_group.add_argument('--decrypt', action='store_true', help='Режим дешифрования')

    # Аргументы
    parser.add_argument('--aes-256-ccm', action='store_true', required=True,
                        help='Использовать AES-256-CCM (обязательный флаг)')
    parser.add_argument('--password', required=True,
                        help=f'Пароль (минимум {MIN_PASSWORD_LEN} символов)')

    # Один позиционный аргумент для данных (интерпретация зависит от режима)
    parser.add_argument('data', nargs='?',
                        help='Данные для шифрования (--crypt) или ссылка bobcat:// (--decrypt)')

    args = parser.parse_args()

    # Проверка пароля
    if len(args.password) < MIN_PASSWORD_LEN:
        print(f"Ошибка: Пароль должен содержать минимум {MIN_PASSWORD_LEN} символов",
              file=sys.stderr)
        sys.exit(1)

    if not args.data:
        print("Ошибка: Не указаны данные (позиционный аргумент)", file=sys.stderr)
        sys.exit(1)

    try:
        if args.crypt:
            result = BobcatCrypto.encrypt(args.data, args.password)
            print(result)
        elif args.decrypt:
            result = BobcatCrypto.decrypt(args.data, args.password)
            print(result)
    except ValueError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Неизвестная ошибка: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
