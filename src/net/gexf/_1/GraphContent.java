//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 in JDK 6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2012.05.09 at 10:24:49 AM PDT 
//


package net.gexf._1;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for graph-content complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="graph-content">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice maxOccurs="unbounded" minOccurs="0">
 *         &lt;element ref="{http://www.gexf.net/1.2draft}attributes"/>
 *         &lt;choice>
 *           &lt;element ref="{http://www.gexf.net/1.2draft}nodes"/>
 *           &lt;element ref="{http://www.gexf.net/1.2draft}edges"/>
 *         &lt;/choice>
 *       &lt;/choice>
 *       &lt;attribute name="timeformat" type="{http://www.gexf.net/1.2draft}timeformat-type" />
 *       &lt;attribute name="start" type="{http://www.gexf.net/1.2draft}time-type" />
 *       &lt;attribute name="startopen" type="{http://www.gexf.net/1.2draft}time-type" />
 *       &lt;attribute name="end" type="{http://www.gexf.net/1.2draft}time-type" />
 *       &lt;attribute name="endopen" type="{http://www.gexf.net/1.2draft}time-type" />
 *       &lt;attribute name="defaultedgetype" type="{http://www.gexf.net/1.2draft}defaultedgetype-type" />
 *       &lt;attribute name="idtype" type="{http://www.gexf.net/1.2draft}idtype-type" />
 *       &lt;attribute name="mode" type="{http://www.gexf.net/1.2draft}mode-type" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "graph-content", propOrder = {
    "attributesOrNodesOrEdges"
})
public class GraphContent {

    @XmlElements({
        @XmlElement(name = "edges", type = EdgesContent.class),
        @XmlElement(name = "attributes", type = AttributesContent.class),
        @XmlElement(name = "nodes", type = NodesContent.class)
    })
    protected List<Object> attributesOrNodesOrEdges;
    @XmlAttribute
    protected TimeformatType timeformat;
    @XmlAttribute
    protected String start;
    @XmlAttribute
    protected String startopen;
    @XmlAttribute
    protected String end;
    @XmlAttribute
    protected String endopen;
    @XmlAttribute
    protected DefaultedgetypeType defaultedgetype;
    @XmlAttribute
    protected IdtypeType idtype;
    @XmlAttribute
    protected ModeType mode;

    /**
     * Gets the value of the attributesOrNodesOrEdges property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the attributesOrNodesOrEdges property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAttributesOrNodesOrEdges().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link EdgesContent }
     * {@link AttributesContent }
     * {@link NodesContent }
     * 
     * 
     */
    public List<Object> getAttributesOrNodesOrEdges() {
        if (attributesOrNodesOrEdges == null) {
            attributesOrNodesOrEdges = new ArrayList<Object>();
        }
        return this.attributesOrNodesOrEdges;
    }

    /**
     * Gets the value of the timeformat property.
     * 
     * @return
     *     possible object is
     *     {@link TimeformatType }
     *     
     */
    public TimeformatType getTimeformat() {
        return timeformat;
    }

    /**
     * Sets the value of the timeformat property.
     * 
     * @param value
     *     allowed object is
     *     {@link TimeformatType }
     *     
     */
    public void setTimeformat(TimeformatType value) {
        this.timeformat = value;
    }

    /**
     * Gets the value of the start property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getStart() {
        return start;
    }

    /**
     * Sets the value of the start property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setStart(String value) {
        this.start = value;
    }

    /**
     * Gets the value of the startopen property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getStartopen() {
        return startopen;
    }

    /**
     * Sets the value of the startopen property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setStartopen(String value) {
        this.startopen = value;
    }

    /**
     * Gets the value of the end property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEnd() {
        return end;
    }

    /**
     * Sets the value of the end property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEnd(String value) {
        this.end = value;
    }

    /**
     * Gets the value of the endopen property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEndopen() {
        return endopen;
    }

    /**
     * Sets the value of the endopen property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEndopen(String value) {
        this.endopen = value;
    }

    /**
     * Gets the value of the defaultedgetype property.
     * 
     * @return
     *     possible object is
     *     {@link DefaultedgetypeType }
     *     
     */
    public DefaultedgetypeType getDefaultedgetype() {
        return defaultedgetype;
    }

    /**
     * Sets the value of the defaultedgetype property.
     * 
     * @param value
     *     allowed object is
     *     {@link DefaultedgetypeType }
     *     
     */
    public void setDefaultedgetype(DefaultedgetypeType value) {
        this.defaultedgetype = value;
    }

    /**
     * Gets the value of the idtype property.
     * 
     * @return
     *     possible object is
     *     {@link IdtypeType }
     *     
     */
    public IdtypeType getIdtype() {
        return idtype;
    }

    /**
     * Sets the value of the idtype property.
     * 
     * @param value
     *     allowed object is
     *     {@link IdtypeType }
     *     
     */
    public void setIdtype(IdtypeType value) {
        this.idtype = value;
    }

    /**
     * Gets the value of the mode property.
     * 
     * @return
     *     possible object is
     *     {@link ModeType }
     *     
     */
    public ModeType getMode() {
        return mode;
    }

    /**
     * Sets the value of the mode property.
     * 
     * @param value
     *     allowed object is
     *     {@link ModeType }
     *     
     */
    public void setMode(ModeType value) {
        this.mode = value;
    }

}
