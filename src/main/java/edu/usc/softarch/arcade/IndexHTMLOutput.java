package edu.usc.softarch.arcade;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;


/**
* This class has one method which creates an the index HTML File for security clustering
* @author CS578 team project
*/
public class IndexHTMLOutput 
{
	public void writeOutput(String [] htmlFileNames, String [] linkNames, String systemName, String outputName) 
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
		
		
		
		// HTML Page Top
		out.println("<!DOCTYPE html>" 
				+"<head>"
				+ "<style>"
				+ style()
				+ "</style>"
				+"</head>"
				+"<body>" 
				+"<h1 class='security-title'>Security Related Decisions for "+systemName+"</h1>"
				);
		
		for (int i = 0; i < htmlFileNames.length; i++) {
			out.println("<a href='"+htmlFileNames[i]+"'>"+linkNames[i]+"</a><br>");
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
				+ "";
		
		return styles;
	}
	
}