import colorama

PROMPT_OKPLUS = colorama.Fore.LIGHTGREEN_EX + "[+]" + colorama.Style.RESET_ALL
PROMPT_EXCLAMATION = colorama.Fore.YELLOW + "[!]" + colorama.Style.RESET_ALL
PROMPT_QUESTION = colorama.Fore.LIGHTCYAN_EX + "[?]" + colorama.Style.RESET_ALL
PROMPT_ERROR = colorama.Fore.LIGHTRED_EX + "[X]" + colorama.Style.RESET_ALL

# EXPIRATION
PERMANENT_NO_EXPIRATION = -1

# Severity ID values
SEVERITY_CRITICAL = 4
SEVERITY_HIGH = 3
SEVERITY_MEDIUM = 2
SEVERITY_LOW = 1
SEVERITY_INFO = 0

SEVERITIES = {
    "4": "CRITICAL",
    "3": "HIGH",
    "2": "MEDIUM",
    "1": "LOW",
    "0": "INFO"
}

LOGO = [
    colorama.Fore.YELLOW +
    "____    ____  __    __   __      .__   __.    ______     ___           _______.___________. _______ .______",
    "\\   \\  /   / |  |  |  | |  |     |  \\ |  |   /      |   /   \\         /       |           ||   ____||   _  \\",
    " \\   \\/   /  |  |  |  | |  |     |   \\|  |  |  ,----'  /  ^  \\       |   (----`---|  |----`|  |__   |  |_)  |",
    "  \\      /   |  |  |  | |  |     |  . `  |  |  |      /  /_\\  \\       \\   \\       |  |     |   __|  |      /     ",
    "   \\    /    |  `--'  | |  `----.|  |\\   |  |  `----./  _____  \\  .----)   |      |  |     |  |____ |  |\\  \\----.",
    "    \\__/      \\______/  |_______||__| \\__|   \\______/__/     \\__\\ |_______/       |__|     |_______|| _| `._____|"
    + colorama.Fore.RESET + colorama.Fore.WHITE + colorama.Style.BRIGHT +
    "\n\t\\"
    "\n\t \\____ Casting vulnerabilities in a galaxy far, far away.\n" + colorama.Style.RESET_ALL
]