import os
import random
import sys

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False

# Shades of green (ANSI 256-color escape codes) used to colorize output.
GREEN_SHADES = [
    '\x1b[38;5;28m',
    '\x1b[38;5;34m',
    '\x1b[38;5;40m',
    '\x1b[38;5;46m',
    '\x1b[38;5;82m',
    '\x1b[38;5;118m',
]
RESET = '\x1b[0m'


def colorize(text, index):
    shade = GREEN_SHADES[index % len(GREEN_SHADES)]
    return f"{shade}{text}{RESET}"


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    print(colorize('★ Made by Ciga ★', 3))
    print()
    banner = [
        ' █████╗ ███╗   ███╗ █████╗ ███████╗ ██████╗ ███╗   ██╗     ██████╗  ██████╗     ██████╗ ███████╗███╗   ██╗',
        '██╔══██╗████╗ ████║██╔══██╗╚══███╔╝██╔═══██╗████╗  ██║    ██╔════╝ ██╔════╝    ██╔════╝ ██╔════╝████╗  ██║',
        '███████║██╔████╔██║███████║  ███╔╝ ██║   ██║██╔██╗ ██║    ██║  ███╗██║         ██║  ███╗█████╗  ██╔██╗ ██║',
        '██╔══██║██║╚██╔╝██║██╔══██║ ███╔╝  ██║   ██║██║╚██╗██║    ██║   ██║██║         ██║   ██║██╔══╝  ██║╚██╗██║',
        '██║  ██║██║ ╚═╝ ██║██║  ██║███████╗╚██████╔╝██║ ╚████║    ╚██████╔╝╚██████╗    ╚██████╔╝███████╗██║ ╚████║',
        '╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝     ╚═════╝  ╚═════╝     ╚═════╝ ╚══════╝╚═╝  ╚═══╝',
    ]
    for i, line in enumerate(banner):
        print(colorize(line, i))
    print()


def print_footer():
    print(colorize('Thank you for using the checker!', 4))


def generate_code():
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    segment1 = ''.join(random.choice(chars) for _ in range(4))
    segment2 = ''.join(random.choice(chars) for _ in range(6))
    segment3 = ''.join(random.choice(chars) for _ in range(5))
    return f"{segment1}-{segment2}-{segment3}"


def generate_codes(quantity):
    all_codes = [generate_code() for _ in range(quantity)]

    print()
    print(colorize('Generated codes:', 1))
    print()
    for code in all_codes:
        print(colorize(code, 3))

    with open('generated_codes.txt', 'w') as f:
        f.write('\n'.join(all_codes))

    print()
    print(colorize("All codes saved to 'generated_codes.txt'.", 2))

    if CLIPBOARD_AVAILABLE:
        pyperclip.copy('\n'.join(all_codes))
        print(colorize('All codes copied to clipboard.', 2))
    else:
        print(colorize("To enable auto-copy to clipboard, install 'pyperclip' package.", 0))


def print_menu():
    print(colorize('╭────────────────────────────╮', 0))
    print(colorize('│      Select an Amount      │', 1))
    print(colorize('├────────────────────────────┤', 2))
    print(colorize('│ 1. Generate 1 Code         │', 3))
    print(colorize('│ 2. Generate 100 Codes      │', 4))
    print(colorize('│ 3. Generate 1000 Codes     │', 5))
    print(colorize('│ 4. Generate 10000 Codes    │', 0))
    print(colorize('│ 5. Exit                    │', 1))
    print(colorize('╰────────────────────────────╯', 2))


def main():
    while True:
        clear()
        print_banner()
        print_menu()

        choice = input(colorize('Your choice: ', 3)).strip()

        if choice == '1':
            generate_codes(1)
        elif choice == '2':
            generate_codes(100)
        elif choice == '3':
            generate_codes(1000)
        elif choice == '4':
            generate_codes(10000)
        elif choice == '5':
            print()
            print(colorize('Exiting... Goodbye!', 0))
            break
        else:
            print(colorize('Invalid choice. Try again.', 0))

        input(colorize('\nPress Enter to continue...', 4))

    print_footer()


if __name__ == '__main__':
    main()
