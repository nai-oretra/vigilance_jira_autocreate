# vigilance_jira_autocreate
A Simply code to autocreate jira's issue with Vigilance (Vigil@nce) vulnerability bulletin. 
this is functionnal with a Vigilance functionnal account : https://vigilance.fr/ and a Jira On Premise installation. 
I will add a CRON task to create issue every day (without week-end) when it's possible. 

TODO : 
I want to autodetect when it's a linux's package (Ubuntu, redhat, Debian...) and add the information like the CVSS score, if the OS is affected or not etc... See you soon
# What do you need : 
* Python 3
* Jira (pip install jira)
* An Vigilance account of course
* Get flower for your wife but it's not obligatory (but it's very advised :D )


# How it's work : 
It's very easy. 
* Download the project
* Extract to a directory
* Run Windows Powershell in the directory if you are on Windows
* python .\Vigilance_jira.py
![image](https://user-images.githubusercontent.com/59687222/222750758-ab2ff146-279c-4c26-a488-1b2568651381.png)
