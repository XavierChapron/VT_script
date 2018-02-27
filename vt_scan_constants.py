config_file_name = "vt_scan_config.txt"
default_config = {"apikey": "MyApiKeyHere", "save_in_dir": False}


class Enum(tuple):
    __getattr__ = tuple.index


ErrorsCodes = Enum(
    [
        'config_file_corrupted',
        'config_file_none',
        'config_file_bad_language',
        'apikey_invalid_none',
        'apikey_invalid_default',
        'apikey_invalid_char',
        'apikey_invalid_lenght',
        'apikey_refused',
        'no_internet_connexion',
        'input_file_read_error',
        'input_file_no_md5'
    ]
)

ErrorsStrings = {
    'en': {
        ErrorsCodes.config_file_corrupted: "Config file: {file} found corrupted.\nFix it or delete it and relaunch the program to create a default one",
        ErrorsCodes.config_file_none: "No config file found, created a default one in: {file}",
        ErrorsCodes.config_file_bad_language: "Language {lang} unknown, options are: 'en' or 'fr'",
        ErrorsCodes.apikey_invalid_none: "No apikey found, you need to configure it using vt_scan_gui apikey field or manually in vt_scan_config.txt",
        ErrorsCodes.apikey_invalid_default: "Default apikey '{apikey}' found, you need to configure it using vt_scan_gui apikey field or manually in vt_scan_config.txt",
        ErrorsCodes.apikey_invalid_char: "Invalid char '{char}' in apikey '{apikey}' found, you need to fix it using vt_scan_gui apikey field or manually in vt_scan_config.txt",
        ErrorsCodes.apikey_invalid_lenght: "Invalid apikey lenght ({lenght} instead of 64) in apikey '{apikey}', you need to fix it using vt_scan_gui apikey field or manually in vt_scan_config.txt",
        ErrorsCodes.apikey_refused: "Your apikey '{apikey}' seems to be refused by VirusTotal.",
        ErrorsCodes.no_internet_connexion: "You should check your internet connection",
        ErrorsCodes.input_file_read_error: "Error while opening file: {file}",
        ErrorsCodes.input_file_no_md5: "You have to choose a file with no md5s."
    },
    'fr': {
        ErrorsCodes.config_file_corrupted: "Le fichier de configuration: {file} est corrompu.\nRéparez le ou supprimez le et relancer le programme pour restaurer celui par défaut.",
        ErrorsCodes.config_file_none: "Fichier de configuration absent, création d'un par défaut ici : {file}",
        ErrorsCodes.config_file_bad_language: "Langue {lang} inconnue, les options sont : 'en' ou 'fr'",
        ErrorsCodes.apikey_invalid_none: "Aucune clé d'API trouvée, vous devez en configurer une en utilisant le champ apikey de vt_scan_gui ou manuellement dans vt_scan_config.txt",
        ErrorsCodes.apikey_invalid_default: "Clé d'API par défaut '{apikey}' trouvé, vous devez en configurer une en utilisant le champ apikey de vt_scan_gui ou manuellement dans vt_scan_config.txt",
        ErrorsCodes.apikey_invalid_char: "Character invalide '{char}' trové dans la clé d'API '{apikey}', vous devez la corriger en utilisant le champ apikey de vt_scan_gui ou manuellement dans vt_scan_config.txt",
        ErrorsCodes.apikey_invalid_lenght: "Longueur de clé d'API invalide ({lenght} à la place de 64) dans la clé d'API '{apikey}', vous devez la corriger en utilisant le champ apikey de vt_scan_gui ou manuellement dans vt_scan_config.txt",
        ErrorsCodes.apikey_refused: "Votre clé d'API '{apikey}' semble être refusé par VirusTotal.\n si ce n'est pas votre clé d'API, configurez la en utilisant le champ apikey de vt_scan_gui ou manuellement dans vt_scan_config.txt",
        ErrorsCodes.no_internet_connexion: "Problème de connexion à Internet",
        ErrorsCodes.input_file_read_error: "Erreur lors de l'ouverture du fichier : {file}",
        ErrorsCodes.input_file_no_md5: "Le fichier ne contient aucun md5."
    }
}


VariousCodes = Enum(
    [
        'config_load',
        'config_found',
        'config_save',
        'config_file_no_language',
        'file_opening',
        'file_type',
        'file_md5s_nb',
        'scan_complete',
        'warning',
        'error',
        'input_file',
        'apikey',
        'save',
        'no_file',
        'choose_file',
        'save_in_dir',
        'language',
        'run_vt_scan',
        'waiting_vt',
        'vt_scan_title',
        'vt_nonzero',
        'vt_unknown',
        'vt_negative',
        'result',
        'file'
    ]
)

VariousStrings = {
    'en': {
        VariousCodes.config_load: "Loading config...\n",
        VariousCodes.config_found: "Config found:\n{config}\n",
        VariousCodes.config_save: "Config: Saving {property} into config file\n",
        VariousCodes.config_file_no_language: "Language property not found in config file. Using 'en', options are: 'en' or 'fr'.\n",
        VariousCodes.file_opening: "Opening file: {file}\n",
        VariousCodes.file_type: "Found the file to be of type {type}.\n",
        VariousCodes.file_md5s_nb: "Found {nb_md5s} MD5s in this file.\n",
        VariousCodes.scan_complete: "\nScan complete, opening results\n",
        VariousCodes.warning: "\n/!\\ WARNING: {message}\n\n",
        VariousCodes.error: "\n/!\\ ERROR: {message}\n\n",
        VariousCodes.input_file: "Input file:",
        VariousCodes.apikey: "Apikey:",
        VariousCodes.save: "Save",
        VariousCodes.no_file: "No input file selected",
        VariousCodes.choose_file: "Choose a file",
        VariousCodes.save_in_dir: "Save in input file directory",
        VariousCodes.language: "Language:",
        VariousCodes.run_vt_scan: "Run VT Scan",
        VariousCodes.waiting_vt: "VT refuses to answer, the script will retry in 10sec.",
        VariousCodes.vt_scan_title: "VT_Scan by Chapi:",
        VariousCodes.vt_nonzero: "VirusTotal nonzero detections ({nb}):",
        VariousCodes.vt_unknown: "VirusTotal unknown files ({nb}):",
        VariousCodes.vt_negative: "VirusTotal negative results ({nb}):",
        VariousCodes.result: "Result",
        VariousCodes.file: "File"
    },
    'fr': {
        VariousCodes.config_load: "Chargement de la configuration...\n",
        VariousCodes.config_found: "Configuration trouvée :\n{config}\n",
        VariousCodes.config_save: "Configuration: Sauvegarde de {property} dans le fichier de configuration\n",
        VariousCodes.config_file_no_language: "Paramètre de langue abstente de la configuration. Utilisation de 'fr', les options sont : 'en' ou 'fr'.\n",
        VariousCodes.file_opening: "Ouverture du fichier : {file}\n",
        VariousCodes.file_type: "Le fichier est du type {type}.\n",
        VariousCodes.file_md5s_nb: "{nb_md5s} MD5s ont été trouvé dans ce fichier.\n",
        VariousCodes.scan_complete: "\nScan complet, ouverture des resultats\n",
        VariousCodes.warning: "\n/!\\ ATTENTION: {message}\n\n",
        VariousCodes.error: "\n/!\\ ERREUR: {message}\n\n",
        VariousCodes.input_file: "Fichier :",
        VariousCodes.apikey: "Apikey :",
        VariousCodes.save: "Sauvegarder",
        VariousCodes.no_file: "Pas de fichier sélectionné",
        VariousCodes.choose_file: "Choisir un fichier",
        VariousCodes.save_in_dir: "Sauvegarder le rapport",
        VariousCodes.language: "Langue:",
        VariousCodes.run_vt_scan: "Lancer VT Scan",
        VariousCodes.waiting_vt: "VT refuse de répondre, le programme va résssayer dans 10 sec.",
        VariousCodes.vt_scan_title: "VT_Scan par Chapi :",
        VariousCodes.vt_nonzero: "VirusTotal détections non nulles ({nb}):",
        VariousCodes.vt_unknown: "VirusTotal fichiers inconnus ({nb}):",
        VariousCodes.vt_negative: "VirusTotal résulats négatifs ({nb}):",
        VariousCodes.result: "Resultat",
        VariousCodes.file: "Fichier"
    }
}
