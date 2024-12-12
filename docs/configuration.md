# Config Specification

## Overview

The `config.json` file is used to store configuration data for our application. This document outlines the specification for the config file, including the required structure and formatting.

## Format

The `config.json` file is a JSON file, which means it must follow the standard JSON syntax rules. The file should contain a single JSON object, which can have multiple properties and nested objects.

## Properties

The following properties are currently supported in the `config.json` file:

- `urls`: an array of url objects
- `acceptable_status_codes`: an array of integers representing acceptable HTTP status codes (default is `[200]`)
- `check_type`: a string representing the type of check to perform (`ping` or `http`, default is `http`)
- `maintenance`: a boolean value indicating whether the application is in maintenance mode (default is `false`)
- `retries`: an integer representing the number of retries to attempt before marking an endpoint as down (default is `0`)
- `retry_interval_seconds`: an integer representing the interval in seconds between retries (default is `60`)
- `check_interval_seconds`: an integer representing the interval in seconds between checks (default is `60`)

### URL Object

Each url object in the `urls` array should have the following properties:

- `name`: a string representing the name of the endpoint
- `url`: a string representing the URL of the endpoint

### Example

Here is an example of a valid `config.json` file:

```json
{
  "urls": [
    {
      "name": "Google",
      "url": "https://google.com",
      "acceptable_status_codes": [200]
    },
    {
      "name": "Cloudflare",
      "url": "1.1.1.1",
      "check_type": "ping"
    }
  ]
}
```
