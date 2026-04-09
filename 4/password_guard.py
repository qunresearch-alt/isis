import math
import string
import secrets

class PasswordValidator:
    def __init__(self, min_length=8, check_common=True):
        self.min_length = min_length
        # Список "мусорных" паролей для проверки
        self.blacklist = ["password123", "12345678", "qwertyuiop", "admin1234"] if check_common else []

    def _get_entropy(self, password: str) -> float:
        """
        Рассчитывает информационную энтропию пароля.
        Чем выше число, тем сложнее пароль подобрать перебором.
        """
        if not password:
            return 0
        
        charset_size = 0
        if any(c.islower() for c in password): charset_size += 26
        if any(c.isupper() for c in password): charset_size += 26
        if any(c.isdigit() for c in password): charset_size += 10
        if any(c in string.punctuation for c in password): charset_size += len(string.punctuation)
        
        # Формула: L * log2(размер пула символов)
        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        return round(entropy, 2)

    def analyze(self, password: str) -> dict:
        """
        Проводит детальный анализ пароля и возвращает отчет.
        """
        # 1. Базовые проверки (отладка на пустые значения)
        if not password or not isinstance(password, str):
            return {"valid": False, "score": 0, "errors": ["Пароль должен быть непустой строкой"]}

        errors = []
        # 2. Проверка длины
        if len(password) < self.min_length:
            errors.append(f"Слишком короткий (минимум {self.min_length} симв.)")

        # 3. Проверка состава символов
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_spec = any(c in string.punctuation for c in password)

        if not (has_upper and has_lower):
            errors.append("Нужны буквы в разных регистрах")
        if not has_digit:
            errors.append("Добавьте хотя бы одну цифру")
        if not has_spec:
            errors.append("Добавьте спецсимвол ($, !, # и т.д.)")

        # 4. Проверка на "банальность"
        if password.lower() in self.blacklist:
            errors.append("Этот пароль слишком предсказуем (в черном списке)")

        # 5. Расчет итогового балла (0-5)
        entropy = self._get_entropy(password)
        score = 0
        if not errors:
            if entropy > 40: score = 3
            if entropy > 60: score = 4
            if entropy > 80: score = 5
        else:
            score = max(1, 3 - len(errors)) # Если есть ошибки, балл не выше 2

        return {
            "valid": len(errors) == 0,
            "score": score,
            "entropy": entropy,
            "errors": errors,
            "recommendation": "Надежный пароль" if not errors else "Требует улучшения"
        }

    def generate_strong(self, length=12):
        """Генерирует криптографически стойкий пароль"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
            # Проверяем, чтобы сгенерированный пароль реально был хорошим
            if self.analyze(password)['valid']:
                return password
