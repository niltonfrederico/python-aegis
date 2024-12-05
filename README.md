# Python Aegis

## Overview

Python Aegis is a tool designed to help you generate vulnerabilities report in your project's dependencies. It integrates with GitHub to fetch dependency information and checks for known vulnerabilities using various data sources.

## Features

- Fetches dependency information from GitHub repositories.
- Checks for known vulnerabilities in dependencies.
- Generates detailed reports on vulnerabilities.

## Dependencies

- `python >= 3.13`
- You must have [github cli](https://cli.github.com/) installed.
- You must have [poetry](https://python-poetry.org/docs/#installation) installed.

## Installation

To install the necessary dependencies, run:

```sh
poetry install
```

## Usage

1. Ensure you have the GitHub CLI (`gh`) installed. If not, install it from [GitHub CLI](https://cli.github.com/).

2. Run the script with the following command:

```sh
python aegis.py [OPTIONS] REPOSITORY
```

### Options

- `--debug`: Enable debug mode for more detailed output.

### Arguments

- `REPOSITORY`: The GitHub repository in the format `owner/repository`.

### Example

```sh
python aegis.py --debug myusername/myrepository
```

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss any changes.

## License

This project is licensed under the **GNU Affero General Public License**. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or support, please open an issue on the GitHub repository.
