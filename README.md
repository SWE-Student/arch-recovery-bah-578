# **CS578 ACDC Extension**

  
This course project is part of CS578 Software Architecture Fall 2019 Spring 2020 @ USC

**Authors**

K. Brady Davis

Sijia Liu

Harutyun Minasyan


## **Purpose**

ACDC is an architectural recovery technique that uses algorithms for structural pattern-based clustering. ACDC currently has several patterns such as source file, directory structure, body-header, leaf collection, support library, central dispatcher, and subgraph dominator to create clusters. Our project extends the current ACDC recovery technique to generate clusters that reveals security architectural decision of a system. Our project is able to account the following security-related architecture decisions: authentication/authorization/access control, cryptographic operations, SSL operations, certificate parsing and management, RSA key generation, and public/private key specifications for any system that imports Java security libraries. When traversing through the class graph, any class file that depends on built in java or javax security packages, spring framework security packages or Apache Shiro security packages + a security decision mentioned above will be printed with respective writer. The clustered results will be displayed using HTML format.

  

## **How to Operate Our Program**

  

### Using a terminal

1.  Navigate to the folder that contains the root folder for the package    

2.  Locate your input directory and set up an output directory. Run the following command in the directory of ACDCwithSecurity.jar (in runnable-jar folder of project):
    

  

```bash

java -jar ACDCwithSecurity.jar [input path] [output path] lib

```
  Input path: the absolute path of the subject system to analyze
  Output file: the absolute path of the output folder that will contain all the generated files

3. After the program is done executing, it will display **Done!** Message in console

4.  Navigate to the output folder and view the results.

	a.  Double click on the index.html file to open it in the browser.    
	
	b.  This file should contain links to multiple security decisions. Click on each link to view the components and their respective files involved in a particular security decision.
    

  

### Using Eclipse IDE

1.  Launch Eclipse and choose a workspace
    
2.  Within the workspace: import the maven project from the file system by choosing the ACDC root folder
    
3.  Make sure to use JDK 7+ for the project
    
4.  On the project root folder, run Maven Install by clicking on the **“play”** button and then **“Run As”**
    
5.  Open the Run Configurations by selecting the root folder on the project explorer view, right clicking and hovering over **run as-> Run Configurations**
    
6.  On the Main tab, enter edu.usc.softarch.arcade.AcdcWithSmellDetection in the text field under **Main Class** subsection
    
7.  On the **Arguments** tab, enter [input path] [output path] lib in the text field, where

	a.  Input path: the absolute path of folder containing the subject system to analyze
    
	b.  Output file: the absolute path of the output folder that will contain all the generated files
    

8.  On the **JRE** tab, make sure the Runtime JRE is set to use JDK package
    
9.  Click **“Apply”**
    
10.  Click **“Run”**
    a.  If a prompt asks to proceed with error, click **“Proceed”**
    
12.  After the program is done executing, it will display **Done!** Message in console
    
13.  Navigate to the output folder and you will see the generated files.
    a. Open the INDEX.html and navigate through the links to see the components that are associated with security decisions and their respective files.
    
**May take a few minutes to generate all the result HTML files**

