import password_guard as pg


if __name__ == "__main__":
    validator = pg.PasswordValidator()

    # --- 1. Анализ тестовых паролей ---
    print("=" * 60)
    print("1. АНАЛИЗ ПАРОЛЕЙ")
    print("=" * 60)

    test_passwords = ["123", "password123", "StrongPass!", "admin_root_99", "MySecure@Pass99"]

    print(f"{'Пароль':<18} | {'Балл':<5} | {'Энтропия':<10} | {'Ошибки'}")
    print("-" * 70)

    for p in test_passwords:
        result = validator.analyze(p)
        err_str = ", ".join(result['errors']) if result['errors'] else "Нет"
        print(f"{p:<18} | {result['score']:<5} | {result['entropy']:<10} | {err_str}")

    # --- 2. Демонстрация энтропии ---
    print("\n" + "=" * 60)
    print("2. РАСЧЁТ ЭНТРОПИИ (_get_entropy)")
    print("=" * 60)

    entropy_examples = ["abc", "abc123", "Abc123!", "MySecure@Pass99"]
    for p in entropy_examples:
        entropy = validator._get_entropy(p)
        print(f"  Пароль: {p:<18} → энтропия: {entropy} бит")

    # --- 3. Детальный отчёт по одному паролю ---
    print("\n" + "=" * 60)
    print("3. ДЕТАЛЬНЫЙ ОТЧЁТ (analyze)")
    print("=" * 60)

    detailed = validator.analyze("MySecure@Pass99")
    print(f"  Пароль:        MySecure@Pass99")
    print(f"  Валидный:      {detailed['valid']}")
    print(f"  Балл:          {detailed['score']} / 5")
    print(f"  Энтропия:      {detailed['entropy']} бит")
    print(f"  Ошибки:        {detailed['errors'] if detailed['errors'] else 'Нет'}")
    print(f"  Рекомендация:  {detailed['recommendation']}")

    # --- 4. Генерация надёжных паролей ---
    print("\n" + "=" * 60)
    print("4. ГЕНЕРАЦИЯ ПАРОЛЕЙ (generate_strong)")
    print("=" * 60)

    print("  Стандартные (12 символов):")
    for i in range(3):
        pwd = validator.generate_strong()
        print(f"    [{i+1}] {pwd}")

    print("  Длинные (20 символов):")
    for i in range(2):
        pwd = validator.generate_strong(length=20)
        print(f"    [{i+1}] {pwd}")

    # --- 5. Кастомный валидатор (без проверки чёрного списка) ---
    print("\n" + "=" * 60)
    print("5. КАСТОМНЫЙ ВАЛИДАТОР (check_common=False)")
    print("=" * 60)

    strict_validator = pg.PasswordValidator(min_length=12, check_common=False)
    test = "password123"
    result = strict_validator.analyze(test)
    print(f"  Пароль '{test}' без проверки чёрного списка:")
    print(f"  Ошибки: {', '.join(result['errors']) if result['errors'] else 'Нет'}")

    print("\n" + "=" * 60)
    print("Демонстрация завершена.")
    print("=" * 60)
