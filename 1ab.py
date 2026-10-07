import logging
import sys
import os
import re
import hashlib


# ---------------------------------------------------------------------------
# 1. НАСТРОЙКА ЛОГГЕРА (гарантированная запись в файл и консоль)
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "file_txt.log")
os.makedirs(LOG_DIR, exist_ok=True)

log_format = "%(asctime)s | [%(levelname)-7s] | %(message)s"
date_format = "%Y-%m-%d %H:%M:%S"

# Убираем возможные старые handlers, чтобы basicConfig точно сработал
for h in logging.root.handlers[:]:
    logging.root.removeHandler(h)

file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8", mode="a")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))

logging.basicConfig(
    level=logging.DEBUG,
    format=log_format,
    datefmt=date_format,
    handlers=[console_handler, file_handler],
    force=True,
)

logger = logging.getLogger(__name__)

# Проверка, что запись в файл реально работает
print(f"[INIT] Лог-файл: {LOG_FILE}")
print(f"[INIT] Файл существует: {os.path.exists(LOG_FILE)}")

logger.info("Логгер успешно сконфигурирован")
logger.info("Приложение запущено")


def _flush_handlers():
    """Сбрасывает буферы всех обработчиков — данные сразу идут на диск."""
    for h in logging.root.handlers:
        try:
            h.flush()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 2. МАСКИРОВАНИЕ ПАРОЛЕЙ (Вариант 2)
# ---------------------------------------------------------------------------
def mask_secret(secret: str) -> str:
    if secret is None:
        return "<none>"
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return f"***{digest[:8]}***"


# ---------------------------------------------------------------------------
# 3. ЧЁРНЫЙ СПИСОК ЛОГИНОВ
# ---------------------------------------------------------------------------
BLACKLIST = {
    "admin", "root", "administrator", "user", "guest",
    "test", "superuser", "moderator", "support", "system","admin@gmail.com"
}

# ---------------------------------------------------------------------------
# 4. РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ
#    PHONE_RE принимает форматы: +x-xxx-xxx-xxxx и +x-xxx-xxx-xx-xx
# ---------------------------------------------------------------------------
PHONE_RE = re.compile(r"^\+\d{1,3}-\d{3}-\d{3}-(?:\d{4}|\d{2}-\d{2})$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
PLAIN_LOGIN_RE = re.compile(r"^[A-Za-z0-9_]{5,}$")

PASSWORD_ALLOWED_RE = re.compile(r"^[А-Яа-яЁё0-9!@#$%^&*()_\-+=\[\]{};:'\",.<>/?\\|`~]+$")
HAS_UPPER_CYR = re.compile(r"[А-ЯЁ]")
HAS_LOWER_CYR = re.compile(r"[а-яё]")
HAS_DIGIT     = re.compile(r"\d")
HAS_SPECIAL   = re.compile(r"[!@#$%^&*()_\-+=\[\]{};:'\",.<>/?\\|`~]")


# ---------------------------------------------------------------------------
# 5. ОШИБКА ВАЛИДАЦИИ
# ---------------------------------------------------------------------------
class ValidationError(Exception):
    pass


# ---------------------------------------------------------------------------
# 6. ФУНКЦИИ ВАЛИДАЦИИ
# ---------------------------------------------------------------------------
def validate_login(login: str) -> None:
    if login is None or login == "":
        raise ValidationError("Логин не может быть пустым.")

    if PHONE_RE.match(login):
        logger.debug("Логин распознан как телефон.")
    elif EMAIL_RE.match(login):
        logger.debug("Логин распознан как email.")
    else:
        if len(login) < 5:
            raise ValidationError(
                "Логин-строка должен содержать минимум 5 символов."
            )
        if not PLAIN_LOGIN_RE.match(login):
            raise ValidationError(
                "Логин-строка может содержать только латиницу, "
                "цифры и знак подчёркивания '_'."
            )
        logger.debug("Логин распознан как обычная строка.")

    if login.strip().lower() in BLACKLIST:
        raise ValidationError(
            "Данный логин находится в чёрном списке запрещённых."
        )


def validate_password(password: str) -> None:
    if password is None or password == "":
        raise ValidationError("Пароль не может быть пустым.")

    if len(password) < 7:
        raise ValidationError("Пароль должен содержать минимум 7 символов.")

    if not PASSWORD_ALLOWED_RE.match(password):
        raise ValidationError(
            "Пароль может содержать только кириллицу, "
            "цифры и спецсимволы."
        )

    if not HAS_UPPER_CYR.search(password):
        raise ValidationError(
            "Пароль должен содержать минимум одну заглавную букву кириллицы."
        )

    if not HAS_LOWER_CYR.search(password):
        raise ValidationError(
            "Пароль должен содержать минимум одну строчную букву кириллицы."
        )

    if not HAS_DIGIT.search(password):
        raise ValidationError("Пароль должен содержать минимум одну цифру.")

    if not HAS_SPECIAL.search(password):
        raise ValidationError(
            "Пароль должен содержать минимум один спецсимвол."
        )


def validate_confirmation(password: str, confirm: str) -> None:
    if confirm is None:
        raise ValidationError("Подтверждение пароля не может быть пустым.")
    if password != confirm:
        raise ValidationError("Пароль и подтверждение пароля не совпадают.")


def validate_credentials(login: str, password: str, confirm: str):
    try:
        validate_login(login)
        validate_password(password)
        validate_confirmation(password, confirm)

        logger.info(
            "УСПЕШНЫЙ ЗАПРОС | login=%s | password=%s | confirm=%s | "
            "result=True | Регистрация прошла успешно",
            login,
            mask_secret(password),
            mask_secret(confirm),
        )
        _flush_handlers()
        return True, ""

    except ValidationError as ex:
        logger.error(
            "НЕУСПЕШНЫЙ ЗАПРОС | login=%s | password=%s | confirm=%s | "
            "result=False | error=%s",
            login,
            mask_secret(password),
            mask_secret(confirm),
            str(ex),
        )
        logger.exception("Трассировка стека исключения валидации:")
        _flush_handlers()
        return False, str(ex)

    except Exception as ex:
        logger.critical(
            "КРИТИЧЕСКАЯ ОШИБКА | login=%s | password=%s | confirm=%s | %s",
            login,
            mask_secret(password),
            mask_secret(confirm),
            str(ex),
        )
        logger.exception("Необработанное исключение:")
        _flush_handlers()
        return False, "Внутренняя ошибка сервера."


# ---------------------------------------------------------------------------
# 7. ВВОД
# ---------------------------------------------------------------------------
EXIT_COMMANDS = {"exit", "quit", "q", "выход"}


def ask(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\nПолучен сигнал завершения ввода.")
        raise


# ---------------------------------------------------------------------------
# 8. БЕСКОНЕЧНЫЙ ЦИКЛ
# ---------------------------------------------------------------------------
def main():
    print("=" * 70)
    print(" Комплексная валидация учётных данных (бесконечный режим)")
    print(" Введите 'exit', 'quit', 'q' или 'выход' для завершения.")
    print("=" * 70)

    iteration = 0
    while True:
        iteration += 1
        logger.info("=" * 70)
        logger.info("Начало итерации №%d", iteration)
        _flush_handlers()

        try:
            login = ask("Логин: ").strip()
        except (EOFError, KeyboardInterrupt):
            logger.warning("Завершение работы: прерывание ввода логина.")
            _flush_handlers()
            break

        if login.lower() in EXIT_COMMANDS:
            logger.info("Пользователь запросил выход (команда: %r).", login)
            _flush_handlers()
            print("Завершение работы. До свидания!")
            break

        try:
            password = ask("Пароль: ")
        except (EOFError, KeyboardInterrupt):
            logger.warning("Завершение работы: прерывание ввода пароля.")
            _flush_handlers()
            break

        if password.lower() in EXIT_COMMANDS:
            logger.info("Пользователь запросил выход (пароль-команда: %r).", password)
            _flush_handlers()
            print("Завершение работы. До свидания!")
            break

        try:
            confirm = ask("Подтверждение пароля: ")
        except (EOFError, KeyboardInterrupt):
            logger.warning("Завершение работы: прерывание ввода подтверждения.")
            _flush_handlers()
            break

        result, message = validate_credentials(login, password, confirm)

        print("-" * 70)
        print(f"Результат: {result}")
        print(f"Сообщение: {message if message else '(успех)'}")
        print("-" * 70)

    logger.info("Приложение завершило работу. Всего итераций: %d", iteration)
    _flush_handlers()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logger.critical("Падение приложения в main():")
        logger.exception("Traceback:")
        _flush_handlers()
        raise