def choice_of_rules():
    liste_of_rules_1 = ["rules_hash\pantagrule-master\\rules\hashesorg.v6\pantagrule.hashorg.v6.hybrid.rule.gz",
                        "rules_hash\pantagrule-master\\rules\hashesorg.v6\pantagrule.hashorg.v6.one.rule.gz",
                        "rules_hash\pantagrule-master\\rules\hashesorg.v6\pantagrule.hashorg.v6.popular.rule.gz",
                        "rules_hash\pantagrule-master\\rules\hashesorg.v6\pantagrule.hashorg.v6.random.rule.gz",
                        "rules_hash\pantagrule-master\\rules\hashesorg.v6\pantagrule.hashorg.v6.raw1m.rule.gz"]
    liste_of_rules_2 = ["rules_hash\pantagrule-master\\rules\private.hashorg.royce\pantagrule.hybrid.royce.rule.gz",
                        "rules_hash\pantagrule-master\\rules\private.hashorg.royce\pantagrule.one.royce.rule.gz",
                        "rules_hash\pantagrule-master\\rules\private.hashorg.royce\pantagrule.popular.royce.rule.gz",
                        "rules_hash\pantagrule-master\\rules\private.hashorg.royce\pantagrule.random.royce.rule.gz"]
    liste_of_rules_3 = ["rules_hash\pantagrule-master\\rules\private.v5\pantagrule.private.v5.hybrid.rule.gz",
                        "rules_hash\pantagrule-master\\rules\private.v5\pantagrule.private.v5.one.gz",
                        "rules_hash\pantagrule-master\\rules\private.v5\pantagrule.private.v5.popular.rule.gz",
                        "rules_hash\pantagrule-master\\rules\private.v5\pantagrule.private.v5.random.rule.gz"]
    print("\nRules : ")
    print("(1)  hashesorg.v6")
    print("(2)  private.hashorg.royce")
    print("(3)  private.v5")
    option_rules = str(input("Veuillez entrez la règle : "))
    if option_rules == "1":
        try :
            print("\nParmi le groupe de règle 'hashesorg.v6' : ")
            print("(1)  pantagrule.hashorg.v6.hybrid.rule")
            print("(2)  pantagrule.hashorg.v6.one.rule")
            print("(3)  pantagrule.hashorg.v6.popular.rule")
            print("(4)  pantagrule.hashorg.v6.random.rule")
            print("(5)  pantagrule.hashorg.v6.raw1m.rule")
            option_rules_1 = int(input("Veuillez entrez la règle : "))
            if 1 <= option_rules_1 <= 5:
                rules_1 = liste_of_rules_1[option_rules_1-1]
                return rules_1
            else:
                print("La réponse doit être un numero correspondant au règles")
        except:
            print("La réponse doit être un numero correspondant au règles")
            choice_of_rules()
    if option_rules == "2":
        print("\nParmi le groupe de règle 'private.hashorg.royce' : ")
        print("(1)  pantagrule.hybrid.royce.rule")
        print("(2)  pantagrule.one.royce.rule")
        print("(3)  pantagrule.popular.royce.rule")
        print("(4)  pantagrule.random.royce.rule")
        option_rules_2 = int(input("Veuillez entrez la regles : "))-1
        assert type(option_rules_2)==int, "la reponse doit estre un numero correspondant au règles"
        rules_2 = liste_of_rules_2[option_rules_2]
        return rules_2
    if option_rules == "3":
        print("\nParmi le groupe de règle 'private.v5' : ")
        print("(1)  pantagrule.private.v5.hybrid.rule")
        print("(2)  pantagrule.private.v5.one")
        print("(3)  pantagrule.private.v5.popular.rule")
        print("(4)  pantagrule.private.v5.random.rule")
        option_rules_3 = int(input("Veuillez entrez la regles : "))-1
        assert type(option_rules_3)==int, "la reponse doit estre un numero correspondant au règles"
        rules_3 = liste_of_rules_3[option_rules_3]
        return rules_3
    else:
        choice_of_rules()