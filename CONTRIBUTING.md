# Contributing to libprocman

First off, thank you for considering contributing to **libprocman** — your interest and effort mean a lot! Whether you're fixing bugs, adding new features, improving documentation, or writing tests, your contributions are always welcome.

## 🧭 How to Get Started

1. **Fork** the repository.
2. **Clone** your fork:
   ```sh
   git clone https://github.com/provrb/libprocman.git
   cd libprocman
   ```
3. Create a new branch:
   ```sh
   git checkout -b feature/your-feature-name
   ```

## 🧪 Testing Your Changes

If you make changes to the core library, you must write or update a test in `tests.cpp`. Here’s how:

1. Add a test case that covers the functionality you've added or modified.
2. Use the `Tests` class to define your expected result.
3. Build and run tests:
   ```sh
   cmake -B build -G Ninja
   cmake --build build
   ./build/libprocman.exe
   ```
4. Ensure **all tests pass** before opening a pull request.

## 🎨 Code Style Guidelines

- Follow the existing naming conventions and structure.
- Keep your code clean and readable.
- Prefer clarity over cleverness.
- Avoid unnecessary dependencies.

## 📦 Making a Pull Request

Before submitting a pull request:

- Make sure your branch is up to date with `main`:
  ```sh
  git fetch origin
  git rebase origin/main
  ```
- **Squash commits** if possible for a clean history.
- Write a **clear and descriptive** pull request message.
- Reference any related issue(s) using `#issue_number` syntax.

## ✅ Pull Request Checklist

- [ ] My code follows the project's code style.
- [ ] I have written tests that prove my fix is effective or my feature works.
- [ ] All existing and new tests pass.
- [ ] I have commented my code, especially in hard-to-understand areas.
- [ ] I have squashed related commits where appropriate.

## 🧠 Pro Tips

- New to the project? Look through [issues](https://github.com/provrb/libprocman/issues) labeled `good first issue` or `help wanted`.
- Want to suggest something new? Open an issue before making major changes.
- Need help? Open an issue or join the discussion in existing ones.

Thanks again for helping make **libprocman** better!