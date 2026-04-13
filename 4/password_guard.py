import math
import string
import secrets

class PasswordValidator:
    def __init__(self, min_length=8, check_common=True):
        self.min_length = min_length
        # Список "мусорных" паролей для проверки
        self.blacklist = ["password123", "12345678", "qwertyuiop", "admin1234"] if check_common else []
        # История использованных паролей
        self.password_history = []

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

    def _has_repeating_chars(self, password: str, max_repeat: int = 3) -> bool:
        """
        Проверяет наличие подряд идущих одинаковых символов.
        Например, 'aaaa' или '1111' считаются слабыми.
        """
        count = 1
        for i in range(1, len(password)):
            if password[i] == password[i - 1]:
                count += 1
                if count >= max_repeat:
                    return True
            else:
                count = 1
        return False

    def check_history(self, password: str) -> bool:
        """
        Проверяет, использовался ли пароль ранее.
        Возвращает True если пароль уже был в истории.
        """
        return password in self.password_history

    def add_to_history(self, password: str) -> None:
        """
        Добавляет пароль в историю использованных.
        Хранит не более 10 последних паролей.
        """
        if password not in self.password_history:
            self.password_history.append(password)
            if len(self.password_history) > 10:
                self.password_history.pop(0)

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

        # 5. Проверка на повторяющиеся символы (новая)
        if self._has_repeating_chars(password):
            errors.append("Пароль содержит повторяющиеся символы (например, 'aaa')")

        # 6. Проверка истории паролей (новая)
        if self.check_history(password):
            errors.append("Этот пароль уже использовался ранее")

        # 7. Расчет итогового балла (0-5)
        entropy = self._get_entropy(password)
        score = 0
        if not errors:
            if entropy > 40: score = 3
            if entropy > 60: score = 4
            if entropy > 80: score = 5
        else:
            score = max(1, 3 - len(errors))

        return {
            "valid": len(errors) == 0,
            "score": score,
            "entropy": entropy,
            "errors": errors,
            "recommendation": "Надежный пароль" if not errors else "Требует улучшения"
        }

    def generate_strong(self, length=12):
        """
        Генерирует криптографически стойкий пароль.
        Длину можно задать вручную (минимум 8 символов).
        """
        length = max(length, self.min_length)
        alphabet = string.ascii_letters + string.digits + string.punctuation
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
            if self.analyze(password)['valid']:
                return password

    def get_strength_label(self, score: int) -> str:
        """
        Возвращает текстовую метку надёжности по баллу.
        """
        labels = {
            0: "Недопустимый",
            1: "Очень слабый",
            2: "Слабый",
            3: "Средний",
            4: "Хороший",
            5: "Отличный",
        }
        return labels.get(score, "Неизвестно")
