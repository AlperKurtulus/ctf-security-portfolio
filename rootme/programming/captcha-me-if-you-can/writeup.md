# Captcha Me If You Can Writeup

## Challenge Information
- **Category**: Root-Me Programming
- **Difficulty**: Medium
- **Points**: 25

## Overview
Automated CAPTCHA solving using Tesseract OCR focuses on deciphering CAPTCHA images to effectively bypass them. In this writeup, we delve into the process and share insights gained while tackling the "Captcha Me If You Can" challenge.

## Challenge Description
The challenge presents a web interface that includes base64 embedded images. The goal is to automate the process of solving the CAPTCHA presented.

## Reconnaissance
The challenge URL is: [http://challenge01.root-me.org/programmation/ch8/](http://challenge01.root-me.org/programmation/ch8/). The initial observations revealed that the CAPTCHA mostly consists of alphanumeric characters.

## Solution Approach
The solution involves developing an image preprocessing pipeline which comprises:
- Image Grayscale Conversion
- Median Filtering
- Binary Thresholding

These techniques are vital for enhancing image clarity and preparing it for OCR.

### Exploitation
The exploitation phase references the use of a script `captcha_me_if_you_can.py`. Make sure to install the following prerequisites:
- `pytesseract`
- `beautifulsoup4`

Key techniques include:
- Base64 Data URI parsing
- Image preprocessing applied via PIL filters
- Tesseract configuration using:
  - Page Segmentation Mode (PSM) 7
  - Character Whitelist (specific characters allowed for recognition)

### Technical Details
Familiarity with Page Segmentation Modes (PSM) in Tesseract is crucial. We utilized `requests.Session()` for maintaining persistence during interactions with the web server.

### Lessons Learned
Our endeavors illuminated vital lessons about:
- Optimizing OCR for improved accuracy and error resilience.
- Identifying common pitfalls that could hinder the CAPTCHA solving process.

## Tools Used
- Python Libraries: `Requests`, `BeautifulSoup`, `Pillow`, `Tesseract`

## Performance Statistics
- [Include performance metrics here if applicable]

## References
- Tesseract Documentation: [Tesseract OCR](https://github.com/tesseract-ocr/tesseract)