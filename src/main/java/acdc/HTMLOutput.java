package acdc;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;

import javax.swing.tree.DefaultMutableTreeNode;

/**
* This class has one method which creates an RSF file.
* 
* The string representation of the output is of the format: 
*
* contain parent_node node
*
*/
public class HTMLOutput implements OutputHandler 
{
	public void writeOutput(String outputName, DefaultMutableTreeNode root) 
	{
		PrintWriter out = null;
		try 
		{
			out = new PrintWriter(new BufferedWriter(new FileWriter(outputName)));
		} 
		catch (IOException e) 
		{
			System.err.println(e.getMessage());
		}
		String htmlHeader = "ACDC Security Related Subsystems";
		
		if (outputName.contains("auth")) {
			htmlHeader = "Subsystems that Implement Authorization/Authentication/Access Control Policy Decisions:";
		}
		else if (outputName.contains("cert")) {
			htmlHeader = "Subsystems that implement Certificate Parsing and Management Decisions:";
		}
		else if (outputName.contains("crypto")) {
			htmlHeader = "Subsystems that Implement Cryptographic Operations Decisions:";
		}
		else if (outputName.contains("FULL")) {
			htmlHeader = "";
		}
		else if (outputName.contains("key")) {
			htmlHeader = "Subsystems that Implement Key Specification Decisions:";
		}
		else if (outputName.contains("security")) {
			htmlHeader = "All Subsystems that Implement Security Decisions:";
		}
		else if (outputName.contains("SIMILARITIES")) {
			htmlHeader = "";
		}
		else if (outputName.contains("ssl")) {
			htmlHeader = "Subsystems that Implement SSL Decisions:";
		}
		else if (outputName.contains("interfaces")) {
			htmlHeader = "Subsystems that Implement RSA Key Generation Decisions:";
		}
		
		
		
		Node ncurr, nj, ni, np;
		DefaultMutableTreeNode curr, i, j, pi;
		String last = "";

		Enumeration allNodes = root.breadthFirstEnumeration();

		// Avoid output for the root node
		i = (DefaultMutableTreeNode) allNodes.nextElement();
		
		// HTML Page Top
		out.println("<!DOCTYPE html>" 
				+"<head>"
				+ "<style>"
				+ style()
				+ "</style>"
//				+ "<link rel='stylesheet' type='text/css' href='style.css'>"
				+"</head>"
				+"<body>"
				+ "<a href='./INDEX.html' class='back-button'>"
				+ "Back"
				+ " </a>" 
				+"<h1 class='security-title'>"+htmlHeader+"</h1>");


		
		
		
		

		while (allNodes.hasMoreElements()) 
		{
			i = (DefaultMutableTreeNode) allNodes.nextElement();

			ni = (Node) i.getUserObject();

			pi = (DefaultMutableTreeNode) i.getParent();

			np = (Node) pi.getUserObject();
			
			String cleanNpName = np.getName();
			if (np.getName().startsWith("\"") && !np.getName().endsWith("\"")) {
				cleanNpName = np.getName().substring(1, np.getName().length());
			}
			
			if (pi != root) {
				if (cleanNpName != last) {
					if (last == "") {
						out.println("<div class='component-box'>");
						out.println("<h2>" + cleanNpName + "</h2>" + 
								"<ul>");
					}
					else {
						out.println("</ul></div>" + 
								"<div class='component-box'><h2>" + cleanNpName + "</h2>" + 
								"<ul>");
					}
					
				}
				else {
					out.println("<li>" + ni.getName() + "</li>");
				}
				last = cleanNpName;
				
			}
			
		
//			if (pi != root) out.println("contain " + cleanNpName + " " + ni.getName());
		}
		
		// HTML Page Bottom
		out.println("</body>" + 
				"</html>");
		
		out.close();
	}
	
	private String style() 
	{
		String styles = ".security-title{"
				+ "text-align: center;"
				+ "}\n"
				+ ".component-box{"
				+ "display: inline-block;"
				+ "padding: 1% 1%;"
				+ "margin: 1%;"
				+ "background-color: #03a9f4;"
				+ "color: white;"
				+ "overflow-wrap: break-word;"
				+ "width: 27%;"
				+ "vertical-align: top;"
				+ "}\n"
				+ ".back-button{"
				+ "padding: 2% 3%;"
				+ "margin: 2%;"
				+ "background-color: #292929;"
				+ "color: white;"
				+ "}"
				+ "";
		
		return styles;
	}
	
}