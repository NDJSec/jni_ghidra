<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/NDJSec/jni_ghidra">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">JNI Ghidra</h3>

  <p align="center">
    Ghidra scripts for cleaning up JNI calls for Android RE
    <br />
    <a href="https://github.com/NDJSec/jni_ghidra"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/NDJSec/jni_ghidra/issues">Report Bug</a>
    ·
    <a href="https://github.com/NDJSec/jni_ghidra/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>
<br>

## Android Reverse Engineering PDF [HERE](https://github.com/NDJSec/Android-Reverse-Engineering)
<br>

## Android Reverse Engineering Tools [DroidAnalysis](https://github.com/NDJSec/DroidAnalysis)
<br>

<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]](https://example.com)

JNI_Ghidra, is a plugin built to help speed up the process of static analysis on Native Binaries in Android APKs. This repo expands on the work of Aryx's JNIAnalyzer. This project, is designed to use Jadx to grab all the Native Methods in a given class and fix the corresponding function in Ghidra. JNI_Ghirda will fix both dynamically linked methods, as well as, statically linked methods through the use of the `onLoad()` function. 

<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

* [![Java][Java]][Java-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started
!TODO

### Prerequisites
* Ghidra 11.0 or higher

### Installation
!TODO

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

_For more examples, please refer to the [Documentation](https://example.com)_

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

- [ ] Feature 1
- [ ] Feature 2
- [ ] Feature 3
    - [ ] Nested Feature

See the [open issues](https://github.com/NDJSec/jni_ghidra/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

NDJSec - [@NicolasJanis1](https://twitter.com/NicolasJanis1) - nicolas.d.janis@gmail.com

Project Link: [https://github.com/NDJSec/jni_ghidra](https://github.com/NDJSec/jni_ghidra)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [FindJNIMethods](https://github.com/Ayrx/FindNativeJNIMethods/tree/master)
* [Jadx](https://github.com/skylot/jadx)
* [Ghidra](https://ghidra-sre.org/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/NDJSec/jni_ghidra.svg?style=for-the-badge
[contributors-url]: https://github.com/NDJSec/jni_ghidra/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/NDJSec/jni_ghidra.svg?style=for-the-badge
[forks-url]: https://github.com/NDJSec/jni_ghidra/network/members
[stars-shield]: https://img.shields.io/github/stars/NDJSec/jni_ghidra.svg?style=for-the-badge
[stars-url]: https://github.com/NDJSec/jni_ghidra/stargazers
[issues-shield]: https://img.shields.io/github/issues/NDJSec/jni_ghidra.svg?style=for-the-badge
[issues-url]: https://github.com/NDJSec/jni_ghidra/issues
[license-shield]: https://img.shields.io/github/license/NDJSec/jni_ghidra.svg?style=for-the-badge
[license-url]: https://github.com/NDJSec/jni_ghidra/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/nicolas-janis/
[product-screenshot]: images/screenshot.png
[Java]: https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white
[Java-url]: https://www.java.com/en/