import password_guard as pg


if __name__ == "__main__":
    validator = pg.PasswordValidator()
    
    test_passwords = ["123", "password123", "StrongPass!", "admin_root_99"]
    
    print(f"{'Пароль':<15} | {'Балл':<5} | {'Ошибки'}")
    print("-" * 50)
    
    for p in test_passwords:
        result = validator.analyze(p)
        err_str = ", ".join(result['errors']) if result['errors'] else "Нет"
        print(f"{p:<15} | {result['score']:<5} | {err_str}")

    print("\nПредложение надежного пароля:", validator.generate_strong())
