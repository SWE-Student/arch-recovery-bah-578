package edu.usc.softarch.arcade;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import acdc.ACDC;

import com.google.common.base.Joiner;

import edu.usc.softarch.arcade.antipattern.detection.ArchSmellDetector;
import edu.usc.softarch.arcade.config.Config;
import edu.usc.softarch.arcade.facts.driver.CSourceToDepsBuilder;
import edu.usc.softarch.arcade.facts.driver.JavaSourceToDepsBuilder;
import edu.usc.softarch.arcade.facts.driver.SourceToDepsBuilder;
import edu.usc.softarch.arcade.util.FileUtil;

public class AcdcWithSmellDetection {
	
	static Logger logger = Logger.getLogger(AcdcWithSmellDetection.class);
	
	public static void main(String[] args) throws IOException  {
		PropertyConfigurator.configure(Config.getLoggingConfigFilename());
		
		// inputDirName is a directory where each subdirectory contains a revision or version of the system to be analyzed
		String inputDirName = args[0];
		File inputDir = new File(FileUtil.tildeExpandPath(inputDirName));
		
		// outputDirName is the directory where dependencies rsf files, cluster rsf files, and detected smells ser files are generated
		String outputDirName = args[1];
		File outputDir = new File(FileUtil.tildeExpandPath(outputDirName));
		
		File[] files = inputDir.listFiles();
		Set<File> fileSet = new TreeSet<File>(Arrays.asList(files));
		logger.debug("All files in " + inputDir + ":");
		logger.debug(Joiner.on("\n").join(fileSet));
		for (File file : fileSet) {
			if (file.isDirectory()) {
				logger.debug("Identified directory: " + file.getName());
			}
		}
		for (File vFolder : fileSet) {
			if (vFolder.isDirectory()) {
				single (vFolder, args, outputDir);
			}
		}		
	}
	public static void single (File versionFolder,String[] args, File outputDir) throws FileNotFoundException, IOException{
		logger.debug("Processing directory: " + versionFolder.getName());
		// the revision number is really just the name of the subdirectory, for hadoop I actually name each subdirectory based on the revision number
		String revisionNumber = versionFolder.getName();
		
		// classesDir is the directory in each subdirectory of the dir directory that contains the compiled classes of the subdirectory
		String classesDir = args[2];
		String absoluteClassesDir = versionFolder.getAbsolutePath() + File.separatorChar + classesDir;
		File classesDirFile = new File(absoluteClassesDir);
		if (!classesDirFile.exists())
			return;
		
		
		
		// depsRsfFilename is the file name of the dependencies rsf file (one is created per subdirectory of dir)
		String depsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_deps.rsf"; 
		// @author = KBD
		String securityDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_security_deps.rsf";
		String authDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_auth_deps.rsf";
		String cryptoDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_crypto_deps.rsf";
		String sslDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_ssl_deps.rsf";
		String certDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_cert_deps.rsf";
		String rsaDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_interfaces_deps.rsf";
		String keyDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_key_deps.rsf";
		
		
		// builderArgs include Absolute Classes directory and all dependency rsf directories
		String[] builderArgs = {absoluteClassesDir,depsRsfFilename,
				securityDepsRsfFilename, authDepsRsfFilename,
				cryptoDepsRsfFilename, sslDepsRsfFilename,
				certDepsRsfFilename, rsaDepsRsfFilename,keyDepsRsfFilename};
		
		// Create RSF Files to be populated with deps by builder
		File depsRsfFile = new File(depsRsfFilename);
		File securityDepsRsfFile = new File(securityDepsRsfFilename);
		File authDepsRsfFile = new File(authDepsRsfFilename);
		File cryptoDepsRsfFile = new File(cryptoDepsRsfFilename);
		File sslDepsRsfFile = new File(sslDepsRsfFilename);
		File certDepsRsfFile = new File(certDepsRsfFilename);
		File rsaDepsRsfFile = new File(rsaDepsRsfFilename);
		File keyDepsRsfFile = new File(keyDepsRsfFilename);
		
		
//		if (!depsRsfFile.getParentFile().exists())
//			depsRsfFile.getParentFile().mkdirs();
//		if (!securityDepsRsfFile.getParentFile().exists())
//			securityDepsRsfFile.getParentFile().mkdirs();
//		logger.debug("Get deps for revision " + revisionNumber);
		
		
		System.out.println("Populating RSF Files with Dependencies");
		// populate RSF files with dependencies
		SourceToDepsBuilder builder = new JavaSourceToDepsBuilder();
		builder.build(builderArgs);
		if (builder.getEdges().size() == 0) {
			return;
		}
		
		// acdcClusteredfile is the recovered architecture for acdc, one per subdirectory of dir
//		String acdcClusteredFile = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_acdc_clustered.rsf";
//		String[] acdcArgs = {depsRsfFile.getAbsolutePath(),acdcClusteredFile};
		
//		String securityAcdcClusteredFile = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_security_acdc_clustered.rsf";
		
		
		// Create HTML Output File Directory Names
		String acdcHTMLFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_FULL_acdc_clustered.html";
		String securityAcdcHTMLFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_security_acdc_clustered.html";
		String authAcdcHTMLFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_auth_acdc_clustered.html";
		String cryptoAcdcHTMLFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_crypto_acdc_clustered.html";
		String sslAcdcHTMLFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_ssl_acdc_clustered.html";
		String certAcdcHTMLFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_cert_acdc_clustered.html";
		String rsaAcdcHTMLFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_interfaces_acdc_clustered.html";
		String keyAcdcHTMLFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_key_acdc_clustered.html";
		
		// Create RSF Output File Directory Names
		String acdcRSFFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_FULL_acdc_clustered.rsf";
		String securityAcdcRSFFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_security_acdc_clustered.rsf";
		String authAcdcRSFFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_auth_acdc_clustered.rsf";
		String cryptoAcdcRSFFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_crypto_acdc_clustered.rsf";
		String sslAcdcRSFFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_ssl_acdc_clustered.rsf";
		String certAcdcRSFFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_cert_acdc_clustered.rsf";
		String rsaAcdcRSFFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_interfaces_acdc_clustered.rsf";
		String keyAcdcRSFFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_key_acdc_clustered.rsf";

		// Create arguments with absolute paths for RSF dependencies files as input and HTML Files for output
		String[] acdcArgs = {depsRsfFile.getAbsolutePath(),acdcHTMLFileName};
		String[] securityArgs = {securityDepsRsfFile.getAbsolutePath(),securityAcdcHTMLFileName};
		String[] authArgs = {authDepsRsfFile.getAbsolutePath(),authAcdcHTMLFileName};
		String[] cryptoArgs = {cryptoDepsRsfFile.getAbsolutePath(),cryptoAcdcHTMLFileName};
		String[] sslArgs = {sslDepsRsfFile.getAbsolutePath(),sslAcdcHTMLFileName};
		String[] certArgs = {certDepsRsfFile.getAbsolutePath(),certAcdcHTMLFileName};
		String[] rsaArgs = {rsaDepsRsfFile.getAbsolutePath(),rsaAcdcHTMLFileName};
		String[] keyArgs = {keyDepsRsfFile.getAbsolutePath(),keyAcdcHTMLFileName};
		
		// Create arguments with absolute paths for RSF dependencies files as input and HTML Files for output
		String[] acdcRSFArgs = {depsRsfFile.getAbsolutePath(),acdcRSFFileName};
		String[] securityRSFArgs = {securityDepsRsfFile.getAbsolutePath(),securityAcdcRSFFileName};
		String[] authRSFArgs = {authDepsRsfFile.getAbsolutePath(),authAcdcRSFFileName};
		String[] cryptoRSFArgs = {cryptoDepsRsfFile.getAbsolutePath(),cryptoAcdcRSFFileName};
		String[] sslRSFArgs = {sslDepsRsfFile.getAbsolutePath(),sslAcdcRSFFileName};
		String[] certRSFArgs = {certDepsRsfFile.getAbsolutePath(),certAcdcRSFFileName};
		String[] rsaRSFArgs = {rsaDepsRsfFile.getAbsolutePath(),rsaAcdcRSFFileName};
		String[] keyRSFArgs = {keyDepsRsfFile.getAbsolutePath(),keyAcdcRSFFileName};

		// Create arrays of arguments and FileNames for ACDC
//		String[][] rsfArgs = {securityRSFArgs, authRSFArgs, cryptoRSFArgs, sslRSFArgs, certRSFArgs, rsaRSFArgs, keyRSFArgs,acdcRSFArgs};
		String[][] rsfArgs = {securityRSFArgs, authRSFArgs, cryptoRSFArgs, sslRSFArgs, certRSFArgs, rsaRSFArgs, keyRSFArgs};
		String[][] htmlArgs= {securityArgs, authArgs, cryptoArgs, sslArgs, certArgs, rsaArgs, keyArgs,acdcArgs};
//		String[][] htmlArgs= {securityArgs, authArgs, cryptoArgs, sslArgs, certArgs, rsaArgs, keyArgs};
		File[] rsfInputFiles = {securityDepsRsfFile, authDepsRsfFile, cryptoDepsRsfFile, sslDepsRsfFile, certDepsRsfFile, rsaDepsRsfFile, keyDepsRsfFile, depsRsfFile};
		
		String simHTMLFileName = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_SIMILARITIES.html";
		File simHTMLFile = new File(simHTMLFileName);
		
		
		// Create arrays with the HTML File Names and link Names for the INDEX.html
		String [] htmlFileNames = {securityAcdcHTMLFileName, authAcdcHTMLFileName, cryptoAcdcHTMLFileName, sslAcdcHTMLFileName, certAcdcHTMLFileName, rsaAcdcHTMLFileName, keyAcdcHTMLFileName,acdcHTMLFileName, simHTMLFileName};
		String [] rsfFileNames = {securityAcdcRSFFileName, authAcdcRSFFileName, cryptoAcdcRSFFileName, sslAcdcRSFFileName, certAcdcRSFFileName, rsaAcdcRSFFileName, keyAcdcRSFFileName,acdcRSFFileName};
		
		String [] linkNames = {"All Security", "Authorization", "Cryptographic Operations", "SSL", "Certificate Parsing and Management" , "RSA Key Generation" , "Key Specifications","ACDC Full", "ACDC Security SubSystem Similarity Comparison"};
		String indexHTMLFileName = outputDir.getAbsolutePath() + File.separatorChar + "INDEX.html";
		File indexHTMLFile = new File(indexHTMLFileName);
		
		
		System.out.println("Populating INDEX.html");
		// Populate INDEX.html with directories of HTML Files and Name of the system 
		IndexHTMLOutput output = new IndexHTMLOutput();
		output.writeOutput(htmlFileNames, linkNames, revisionNumber, indexHTMLFileName);
		
		System.out.println("Running ACDC for each RSF File. This may take a minute...");
		// Run ACDC for each of the RSF dependencies Files with corresponding HTML arguments as long as they are not empty
		for (int i = 0; i < htmlArgs.length; i++) {
			BufferedReader Buff = new BufferedReader(new FileReader(rsfInputFiles[i]));
	        String text = Buff.readLine();
	        Buff.close();
	        if (text != "" && text != null) {
	        	ACDC.main(htmlArgs[i]);
	        }
		}
		
		// Run ACDC for each of the RSF dependencies Files with corresponding RSF arguments as long as they are not empty
//		for (int i = 0; i < rsfArgs.length; i++) {
//			BufferedReader Buff = new BufferedReader(new FileReader(rsfInputFiles[i]));
//	        String text = Buff.readLine();
//	        Buff.close();
//	        if (text != "" && text != null) {
//	        	ACDC.main(rsfArgs[i]);
//	        }
//		}
		
		
		
		String[] simDiff = findSimilarities(acdcHTMLFileName, securityAcdcHTMLFileName);
		
		PrintWriter out = null;
		try {
			out = new PrintWriter(new BufferedWriter(new FileWriter(simHTMLFileName)));
		} 
		catch (IOException e) {
			System.err.println(e.getMessage());
		}
		
		
		
		out.println("<!DOCTYPE html><head><style>.security-title{text-align: center;}");
		out.println(".component-box{display: inline-block;padding: 1% 1%;margin: 1%;background-color: #03a9f4;color: white;overflow-wrap: break-word;width: 27%;vertical-align: top;}");
        out.println(".back-button{padding: 2% 3%;margin: 2%;background-color: #292929;color: white;}</style></head><body><a href='./INDEX.html' class='back-button'>Back </a>");
        
		out.println("<h1>Security Related Subsystems</h1>");
		
		out.println(simDiff[0]);
		
		out.println("</ul></div><h1>Non-Security Related Subsystems</h1>");
		out.println(simDiff[1]);
		out.println("</body></html>");
		out.close();
		
		System.out.println("Done!");
		
	}
	
	public static String[] findSimilarities(String largeFilePath, String smallFilePath) throws IOException {
		
         String curr;
         List<String> largeList = new ArrayList<String>();
         List<String> smallList = new ArrayList<String>();
         BufferedReader largeReader = new BufferedReader(new FileReader(largeFilePath));
         BufferedReader smallReader = new BufferedReader(new FileReader(smallFilePath));
       
         while ((curr = largeReader.readLine()) != null) {
             largeList.add(curr);
         }
         while ((curr = smallReader.readLine()) != null) {
             smallList.add(curr);
         }
         
         largeReader.close();
         smallReader.close();
         
         List<String> diffList = new ArrayList<String>(largeList);
         diffList.removeAll(smallList);
         
         List<String> simList = new ArrayList<String>(largeList);
         simList.removeAll(diffList);
         
         StringBuffer simBuf = new StringBuffer();
         for (String s : simList) {
            simBuf.append(s);
         }
         
         StringBuffer diffBuf = new StringBuffer();
         for (String s : diffList) {
            diffBuf.append(s);
         }
         
         String simStr = simBuf.toString();
         String diffStr = diffBuf.toString();
         
         simStr = simStr.replace("</body></html>","");
         simStr = simStr.replace("<!DOCTYPE html><head><style>.security-title{text-align: center;}","");
         simStr = simStr.replace(".component-box{display: inline-block;padding: 1% 1%;margin: 1%;background-color: #03a9f4;color: white;overflow-wrap: break-word;width: 27%;vertical-align: top;}","");
         simStr = simStr.replace(".back-button{padding: 2% 3%;margin: 2%;background-color: #292929;color: white;}</style></head><body><a href='./INDEX.html' class='back-button'>Back </a>","");
         
         diffStr = diffStr.replace("</body></html>","");
         diffStr = diffStr.replace("<!DOCTYPE html><head><style>.security-title{text-align: center;}","");
         diffStr = diffStr.replace(".component-box{display: inline-block;padding: 1% 1%;margin: 1%;background-color: #03a9f4;color: white;overflow-wrap: break-word;width: 27%;vertical-align: top;}","");
         diffStr = diffStr.replace(".back-button{padding: 2% 3%;margin: 2%;background-color: #292929;color: white;}</style></head><body><a href='./INDEX.html' class='back-button'>Back </a>","");
         
         
         
         String[] simDiff = {simStr, diffStr};
         
		return simDiff;
	}
	
	
}
