# Summary

URL Pinger is a simple python application that "pings" a list of endpoints and checks the response time and status code. Refer to our [docs](docs/) folder for more inforamtion.

## Development

URL Pinger is deployed using dex. To get started with development, follow the steps below:

1. Clone the repository
2. Install the required dependencies for local development

   ```bash
   # if you have poetry installed
   poetry install

   # if you don't have poetry installed
   pip install -r requirements.txt
   ```

3. Run the application

   ```bash
   # if you have poetry installed
   poetry run python urlpinger/main.py

   # if you don't have poetry installed
   python urlpinger/main.py
   ```
