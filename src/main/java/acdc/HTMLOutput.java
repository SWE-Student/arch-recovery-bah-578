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
				+"<h1 class='security-title'>ACDC Subsystems that implement Authorization and Authentication</h1>");


		
		
		
		

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
					
//					<h2>An Unordered HTML List</h2>
//
//					<ul>
//					  <li>Coffee</li>
//					  <li>Tea</li>
//					  <li>Milk</li>
//					</ul>  
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
				+ "padding: 5% 3%;"
				+ "margin: 5%;"
				+ "background-color: #64b5f6;"
				+ "color: white;"
				+ "overflow-wrap: break-word;"
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