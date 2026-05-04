# vulnerable_yaml_load.py

import yaml


def load_user_config(config_file_path):
    """
    Vulnerable example:
    This function loads YAML content from a file using yaml.load()
    without specifying yaml.SafeLoader.
    """

    with open(config_file_path, "r", encoding="utf-8") as file:
        config_data = file.read()

    # Semgrep rule bandit.B506 should flag this line
    parsed_config = yaml.load_all(config_data, Loader=yaml.CLoader)
    return parsed_config


def main():
    config = load_user_config("user_config.yaml")

    print("Loaded configuration:")
    print(config)


if __name__ == "__main__":
    main()
