import unittest
import password_guard as pg


class TestPasswordValidator(unittest.TestCase):

    def setUp(self):
        """Создаём валидатор перед каждым тестом"""
        self.validator = pg.PasswordValidator()

    # ─── analyze() ────────────────────────────────────────────────

    def test_empty_string(self):
        """Пустая строка → valid=False, score=0"""
        result = self.validator.analyze("")
        self.assertFalse(result['valid'])
        self.assertEqual(result['score'], 0)

    def test_none_input(self):
        """None → valid=False, score=0"""
        result = self.validator.analyze(None)
        self.assertFalse(result['valid'])
        self.assertEqual(result['score'], 0)

    def test_too_short(self):
        """Пароль короче 8 символов → ошибка о длине"""
        result = self.validator.analyze("123")
        self.assertFalse(result['valid'])
        self.assertTrue(any("короткий" in e for e in result['errors']))

    def test_no_uppercase(self):
        """Только строчные буквы → ошибка о регистре"""
        result = self.validator.analyze("lowercase99!")
        self.assertFalse(result['valid'])
        self.assertTrue(any("регистр" in e for e in result['errors']))

    def test_no_lowercase(self):
        """Только заглавные буквы → ошибка о регистре"""
        result = self.validator.analyze("UPPERCASE99!")
        self.assertFalse(result['valid'])
        self.assertTrue(any("регистр" in e for e in result['errors']))

    def test_no_digit(self):
        """Нет цифр → ошибка о цифре"""
        result = self.validator.analyze("StrongPass!")
        self.assertFalse(result['valid'])
        self.assertTrue(any("цифр" in e for e in result['errors']))

    def test_no_special_char(self):
        """Нет спецсимвола → ошибка о спецсимволе"""
        result = self.validator.analyze("StrongPass99")
        self.assertFalse(result['valid'])
        self.assertTrue(any("спецсимвол" in e for e in result['errors']))

    def test_blacklisted_password(self):
        """Пароль из чёрного списка → ошибка о предсказуемости"""
        result = self.validator.analyze("password123")
        self.assertFalse(result['valid'])
        self.assertTrue(any("чёрном списке" in e or "черном списке" in e for e in result['errors']))

    def test_valid_password(self):
        """Надёжный пароль → valid=True, score=5"""
        result = self.validator.analyze("MySecure@Pass99")
        self.assertTrue(result['valid'])
        self.assertEqual(result['score'], 5)
        self.assertEqual(result['errors'], [])

    def test_score_range(self):
        """Балл всегда в диапазоне 0–5"""
        passwords = ["123", "password123", "StrongPass!", "MySecure@Pass99", "", None]
        for p in passwords:
            result = self.validator.analyze(p)
            self.assertGreaterEqual(result['score'], 0)
            self.assertLessEqual(result['score'], 5)

    def test_returns_dict_with_keys(self):
        """analyze() возвращает словарь с нужными ключами"""
        result = self.validator.analyze("TestPass1!")
        for key in ['valid', 'score', 'entropy', 'errors', 'recommendation']:
            self.assertIn(key, result)

    def test_recommendation_valid(self):
        """Надёжный пароль → рекомендация 'Надежный пароль'"""
        result = self.validator.analyze("MySecure@Pass99")
        self.assertEqual(result['recommendation'], "Надежный пароль")

    def test_recommendation_invalid(self):
        """Слабый пароль → рекомендация 'Требует улучшения'"""
        result = self.validator.analyze("123")
        self.assertEqual(result['recommendation'], "Требует улучшения")

    # ─── _get_entropy() ───────────────────────────────────────────

    def test_entropy_empty(self):
        """Энтропия пустой строки = 0"""
        self.assertEqual(self.validator._get_entropy(""), 0)

    def test_entropy_increases_with_complexity(self):
        """Энтропия растёт по мере усложнения пароля"""
        e1 = self.validator._get_entropy("abc")
        e2 = self.validator._get_entropy("abc123")
        e3 = self.validator._get_entropy("Abc123!")
        self.assertLess(e1, e2)
        self.assertLess(e2, e3)

    def test_entropy_is_float(self):
        """Энтропия возвращается как число"""
        result = self.validator._get_entropy("TestPass1!")
        self.assertIsInstance(result, float)

    # ─── generate_strong() ────────────────────────────────────────

    def test_generate_strong_is_valid(self):
        """Сгенерированный пароль проходит валидацию"""
        pwd = self.validator.generate_strong()
        result = self.validator.analyze(pwd)
        self.assertTrue(result['valid'])

    def test_generate_strong_default_length(self):
        """Длина по умолчанию = 12"""
        pwd = self.validator.generate_strong()
        self.assertEqual(len(pwd), 12)

    def test_generate_strong_custom_length(self):
        """Кастомная длина применяется корректно"""
        pwd = self.validator.generate_strong(length=20)
        self.assertEqual(len(pwd), 20)

    def test_generate_strong_returns_string(self):
        """generate_strong() возвращает строку"""
        pwd = self.validator.generate_strong()
        self.assertIsInstance(pwd, str)

    # ─── Кастомный валидатор ──────────────────────────────────────

    def test_custom_min_length(self):
        """Кастомная минимальная длина работает корректно"""
        validator = pg.PasswordValidator(min_length=12)
        result = validator.analyze("Short1!")
        self.assertTrue(any("короткий" in e for e in result['errors']))

    def test_check_common_disabled(self):
        """При check_common=False пароль из чёрного списка не блокируется по этому критерию"""
        validator = pg.PasswordValidator(check_common=False)
        result = validator.analyze("password123")
        self.assertFalse(any("черном списке" in e or "чёрном списке" in e for e in result['errors']))


if __name__ == "__main__":
    unittest.main(verbosity=2)
