package edu.usc.softarch.arcade;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

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
	public static void single (File versionFolder,String[] args,File outputDir) throws FileNotFoundException, IOException{
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
		String authDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_auth_deps.rsf";
		String cryptoDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_crypto_deps.rsf";
		String sslDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_ssl_deps.rsf";
		String certDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_cert_deps.rsf";
		String rsaDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_interfaces_deps.rsf";
		String keyDepsRsfFilename = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_key_deps.rsf";
		
//		String[] builderArgs = {absoluteClassesDir,depsRsfFilename};
		String[] builderArgs = {absoluteClassesDir,depsRsfFilename,authDepsRsfFilename, cryptoDepsRsfFilename, sslDepsRsfFilename, certDepsRsfFilename, rsaDepsRsfFilename, keyDepsRsfFilename};
		
		File depsRsfFile = new File(depsRsfFilename);
		
		File authDepsRsfFile = new File(authDepsRsfFilename);
		File cryptoDepsRsfFile = new File(cryptoDepsRsfFilename);
		File sslDepsRsfFile = new File(sslDepsRsfFilename);
		File certDepsRsfFile = new File(certDepsRsfFilename);
		File rsaDepsRsfFile = new File(rsaDepsRsfFilename);
		File keyDepsRsfFile = new File(keyDepsRsfFilename);
		
		if (!depsRsfFile.getParentFile().exists())
			depsRsfFile.getParentFile().mkdirs();
//		if (!securityDepsRsfFile.getParentFile().exists())
//			securityDepsRsfFile.getParentFile().mkdirs();
		
		logger.debug("Get deps for revision " + revisionNumber);
		
		SourceToDepsBuilder builder = new JavaSourceToDepsBuilder();
		
		builder.build(builderArgs);
		if (builder.getEdges().size() == 0) {
			return;
		}
		
		// acdcClusteredfile is the recovered architecture for acdc, one per subdirectory of dir
		String acdcClusteredFile = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_acdc_clustered.rsf";
		String[] acdcArgs = {depsRsfFile.getAbsolutePath(),acdcClusteredFile};
		
//		String securityAcdcClusteredFile = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_security_acdc_clustered.rsf";
		
		String authAcdcHTMLFile = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_auth_acdc_clustered.html";
		String cryptoAcdcHTMLFile = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_crypto_acdc_clustered.html";
		String sslAcdcHTMLFile = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_ssl_acdc_clustered.html";
		String certAcdcHTMLFile = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_cert_acdc_clustered.html";
		String rsaAcdcHTMLFile = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_interfaces_acdc_clustered.html";
		String keyAcdcHTMLFile = outputDir.getAbsolutePath() + File.separatorChar + revisionNumber + "_key_acdc_clustered.html";
		
//		authDepsRsfFile
//		cryptoDepsRsfFile
//		sslDepsRsfFile
//		certDepsRsfFile
//		rsaDepsRsfFile
//		keyDepsRsfFile
		
//		String[] authArgs = {authDepsRsfFile.getAbsolutePath(),authAcdcHTMLFile};
//		String[] cryptoArgs = {cryptoDepsRsfFile.getAbsolutePath(),cryptoAcdcHTMLFile};
//		String[] sslArgs = {sslDepsRsfFile.getAbsolutePath(),sslAcdcHTMLFile};
//		String[] certArgs = {certDepsRsfFile.getAbsolutePath(),certAcdcHTMLFile};
//		String[] rsaArgs = {rsaDepsRsfFile.getAbsolutePath(),rsaAcdcHTMLFile};
		String[] keyArgs = {keyDepsRsfFile.getAbsolutePath(),keyAcdcHTMLFile};
		
		logger.debug("Running acdc for revision " + revisionNumber);
//		ACDC.main(acdcArgs);

//		ACDC.main(authArgs);
//		ACDC.main(cryptoArgs);
//		ACDC.main(sslArgs);
//		ACDC.main(certArgs);
//		ACDC.main(rsaArgs);
		ACDC.main(keyArgs);
		
		
		// the last element of the smellArgs array is the location of the file containing the detected smells (one is created per subdirectory of dir)
		/*
		 * String[] smellArgs =
		 * {depsRsfFile.getAbsolutePath(),acdcClusteredFile,outputDir.getAbsolutePath()
		 * + File.separatorChar + revisionNumber + "_acdc_smells.ser"};
		 * logger.debug("Running smell detecion for revision " + revisionNumber);
		 * ArchSmellDetector.setupAndRunStructuralDetectionAlgs(smellArgs);
		 */
	}
}
