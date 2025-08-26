# Automated Cybersecurity Vulnerability Scanner

This project is an Automated Cybersecurity Vulnerability Scanner that scrapes websites for the latest cybersecurity vulnerabilities, uses a Large Language Model (LLM) to extract key information, and generates a consolidated report.

-----

## Project Overview

The application is built with Python and utilizes a web-based interface created with Streamlit. It automates the process of gathering vulnerability data from various online sources, parsing the relevant details, and presenting them in a clean, downloadable text file.

-----

## Features

  * **Web Scraping**: Automatically scrapes a predefined list of websites known for publishing cybersecurity news and vulnerability disclosures.
  * **AI-Powered Parsing**: Leverages the Google Gemini model to intelligently parse the scraped content, extracting vulnerability names and their corresponding solutions.
  * **Report Generation**: Generates a `vulnerability_report.txt` file containing the extracted information.
  * **User-Friendly Interface**: A simple web interface built with Streamlit allows users to start the scan and download the final report with a single click.

-----

## How It Works

1.  **Get URLs**: The scraper starts with a list of target URLs from the `get_vulnerability_urls` function in `scrape.py`.
2.  **Scrape Content**: For each URL, it uses Selenium to load the page and extract the raw HTML content.
3.  **Clean Content**: The HTML is cleaned to remove scripts, styles, and unnecessary tags, leaving only the main text content.
4.  **Parse with AI**: The cleaned text is then sent to the Gemini model with a prompt to identify and extract vulnerabilities and solutions.
5.  **Generate Report**: The extracted information is compiled into a single text file that can be downloaded from the Streamlit interface.

-----

## Setup and Installation

To run this project locally, follow these steps:

1.  **Prerequisites**

      * Python 3.8 or higher
      * pip (Python package installer)

2.  **Clone the repository** (or ensure all project files are in the same directory)

    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

3.  **Create a virtual environment** (recommended)

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

4.  **Install dependencies**
    Install all the required packages using the `requirements.txt` file.

    ```bash
    pip install -r requirements.txt
    ```

5.  **Set up environment variables**
    The application requires a Google API key to use the Gemini model. Create a file named `.env` in the root directory of the project and add your API key as follows:

    ```
    GOOGLE_API_KEY="YOUR_GOOGLE_API_KEY"
    ```

-----

## Usage

Once the setup is complete, you can run the Streamlit application with the following command:

```bash
streamlit run main.py
```

This will open a new tab in your web browser with the application's user interface. Click the **"Generate Vulnerability Report"** button to start the scanning process. Once completed, a download button will appear, allowing you to save the generated report.

-----

## Dependencies

This project relies on the following major Python libraries:

  * **streamlit**: For creating the web application interface.
  * **langchain & langchain\_google\_genai**: For interacting with the Gemini Large Language Model.
  * **selenium**: For automating web browser interaction and scraping dynamic content.
  * **beautifulsoup4**: For parsing HTML and XML documents.
  * **python-dotenv**: For managing environment variables.
  * **webdriver-manager**: For managing the Selenium WebDriver binary.
