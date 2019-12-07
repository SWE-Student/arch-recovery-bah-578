package edu.usc.softarch.arcade.facts.driver;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import com.google.common.base.Joiner;

import classycle.Analyser;
import classycle.ClassAttributes;
import classycle.graph.AtomicVertex;
import edu.usc.softarch.arcade.clustering.FastFeatureVectors;
import edu.usc.softarch.arcade.clustering.FeatureVectorMap;
import edu.usc.softarch.arcade.config.Config;
import edu.usc.softarch.arcade.functiongraph.TypedEdgeGraph;
import edu.usc.softarch.arcade.util.FileUtil;

import edu.usc.softarch.arcade.SecurityDictionary;

public class JavaSourceToDepsBuilder implements SourceToDepsBuilder {
	
	static Logger logger = Logger.getLogger(JavaSourceToDepsBuilder.class);

	public Set<Pair<String,String>> edges;
	public static FastFeatureVectors ffVecs = null;
	public int numSourceEntities = 0;
	
//	@Override
	public Set<Pair<String,String>> getEdges() {
		return this.edges;
	}
	
//	@Override
	public int getNumSourceEntities() {
		return this.numSourceEntities;
	}

	public static void main(String[] args) throws IOException {
		(new JavaSourceToDepsBuilder()).build(args);
	}

	public void build(String[] args) throws IOException,
			FileNotFoundException {
		PropertyConfigurator.configure(Config.getLoggingConfigFilename());
		
		String[] inputClasses = { FileUtil.tildeExpandPath(args[0]) };
		String depsRsfFilename = FileUtil.tildeExpandPath(args[1]);
		
//		authDepsRsfFile
//		cryptoDepsRsfFile
//		sslDepsRsfFile
//		certDepsRsfFile
//		rsaDepsRsfFile
//		keyDepsRsfFile
		
		// CS578 Team Project
		String securityDepsRsfFilename = FileUtil.tildeExpandPath(args[2]);
		String authDepsRsfFilename = FileUtil.tildeExpandPath(args[3]);
		String cryptoDepsRsfFilename = FileUtil.tildeExpandPath(args[4]);
		String sslDepsRsfFilename = FileUtil.tildeExpandPath(args[5]);
		String certDepsRsfFilename = FileUtil.tildeExpandPath(args[6]);
		String rsaDepsRsfFilename = FileUtil.tildeExpandPath(args[7]);
		String keyDepsRsfFilename = FileUtil.tildeExpandPath(args[8]);
		
		Analyser analyzer = new Analyser(inputClasses);
		analyzer.readAndAnalyse(false);
		//analyzer.printRaw(new PrintWriter(System.out));
		
		PrintStream securityOut = new PrintStream(securityDepsRsfFilename);
		PrintWriter securityWriter = new PrintWriter(securityOut);
		
		PrintStream authOut = new PrintStream(authDepsRsfFilename);
		PrintWriter authWriter = new PrintWriter(authOut);
		
		PrintStream cryptoOut = new PrintStream(cryptoDepsRsfFilename);
		PrintWriter cryptoWriter = new PrintWriter(cryptoOut);
		
		PrintStream sslOut = new PrintStream(sslDepsRsfFilename);
		PrintWriter sslWriter = new PrintWriter(sslOut);
		
		PrintStream certOut = new PrintStream(certDepsRsfFilename);
		PrintWriter certWriter = new PrintWriter(certOut);
		
		PrintStream rsaOut = new PrintStream(rsaDepsRsfFilename);
		PrintWriter rsaWriter = new PrintWriter(rsaOut);
		
		PrintStream keyOut = new PrintStream(keyDepsRsfFilename);
		PrintWriter keyWriter = new PrintWriter(keyOut);

		PrintStream out = new PrintStream(depsRsfFilename);
		PrintWriter writer = new PrintWriter(out);
		AtomicVertex[] graph = analyzer.getClassGraph();
		
		edges = new LinkedHashSet<Pair<String,String>>();
		for (int i = 0; i < graph.length; i++) {
			AtomicVertex vertex = graph[i];
			ClassAttributes sourceAttributes = (ClassAttributes)vertex.getAttributes();
			//writer.println(sourceAttributes.getType() +  " " + sourceAttributes.getName());
			for (int j = 0, n = vertex.getNumberOfOutgoingArcs(); j < n; j++) {
				ClassAttributes targetAttributes = (ClassAttributes)vertex.getHeadVertex(j).getAttributes();
				//writer.println("    " + targetAttributes.getType() + " " + targetAttributes.getName());
				Pair<String,String> edge = new ImmutablePair<String,String>(sourceAttributes.getName(),targetAttributes.getName());
				edges.add(edge);
			}
		}
		
		
		// CS578 Team Project
		SecurityDictionary sd = new SecurityDictionary();
		
		for (Pair<String,String> edge : edges) {
			writer.println("depends " + edge.getLeft() + " " + edge.getRight());
			
			// All Java Security Dependencies:
			for (String fw : sd.getSecurityFrameworks()) {
				if (edge.getRight().contains(fw))
					securityWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
			}
			// Authorization Dependencies:
			for (String fw : sd.getAuthPackages()) {
				if (edge.getRight().contains(fw))
					authWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
			}
			// Certificate Parsing and Management Dependencies:
			for (String fw : sd.getCertPackages()) {
				if (edge.getRight().contains(fw))
					certWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
			}
			// Cryptographic Operations Dependencies:
			for (String fw : sd.getCryptoPackages()) {
				if (edge.getRight().contains(fw))
					cryptoWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
			}
			// Key Specification Dependencies:
			for (String fw : sd.getKeyPackages()) {
				if (edge.getRight().contains(fw))
					keyWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
			}
			// RSA Key Generation Dependencies:
			for (String fw : sd.getRsaPackages()) {
				if (edge.getRight().contains(fw))
					rsaWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
			}
			// SSL Dependencies:
			for (String fw : sd.getSslPackages()) {
				if (edge.getRight().contains(fw))
					sslWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
			}
			
//			if (edge.getRight().contains("javax.security") || edge.getRight().contains("java.security")) {
//				securityWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
//			}	
//			
//			// Authorization Dependencies:
//			if (edge.getRight().contains("javax.security.auth")) {
//				authWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
//			}
//			// Cryptographic Operations Dependencies:
//			else if (edge.getRight().contains("javax.crypto") || edge.getRight().contains("javax.xml.crypto")) {
//				cryptoWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
//			}
//			// SSL Dependencies
//			else if (edge.getRight().contains("javax.net.ssl") || edge.getRight().contains("javax.rmi.ssl")) {
//				sslWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
//			}
//			// Certificate Parsing and Management Dependencies
//			else if (edge.getRight().contains("java.security.cert") || edge.getRight().contains("javax.security.cert")) {
//				certWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
//			}
//			// RSA Key Generation Dependencies
//			else if (edge.getRight().contains("java.security.interfaces")) {
//				rsaWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
//			}
//			// Key Specification Dependencies
//			else if (edge.getRight().contains("java.security.spec")) {
//				keyWriter.println("depends " + edge.getLeft() + " " + edge.getRight());
//			}
		}
		
		writer.close();
		securityWriter.close();
		authWriter.close();
		cryptoWriter.close();
		sslWriter.close();
		certWriter.close();
		rsaWriter.close();
		keyWriter.close();
		
		
		Set<String> sources = new HashSet<String>();
		for (Pair<String,String> edge : edges) {
			sources.add(edge.getLeft());
		}
		numSourceEntities = sources.size();
		
		TypedEdgeGraph typedEdgeGraph = new TypedEdgeGraph();
		for (Pair<String,String> edge : edges) {
			typedEdgeGraph.addEdge("depends",edge.getLeft(),edge.getRight());
		}
		
		FeatureVectorMap fvMap = new FeatureVectorMap(typedEdgeGraph);
		ffVecs = fvMap.convertToFastFeatureVectors();
	}

//	@Override
	public FastFeatureVectors getFfVecs() {
		return this.ffVecs;
	}

}
