from config import Config

config = Config()

def choice_of_rules():
    for i in range(len(config.LIST_RULES)):
        print(f"{i+1} - {config.LIST_RULES[i]}")

    option_rules = int(input("Veuillez entrez la règle : "))
    if 1 <= option_rules <= len(config.LIST_RULES):
        return config.LIST_RULES[option_rules - 1]
    else:
        return choice_of_rules()