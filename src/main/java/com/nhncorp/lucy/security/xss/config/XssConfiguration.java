package com.nhncorp.lucy.security.xss.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.nhncorp.lucy.security.xss.event.ElementListener;

/**
 * 이 클래스는 XSS Filter 설정 내용을 나타낸다. <br/>
 * 만약, 설정 내용을 담고 있는 파일이 존재 하지 않거나 예상치 못한 포멧을 가지고 있다면, Exception을 발생 시킨다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 19999 $, $Date: 2009-01-28 16:17:59 +0900 (수, 28 1 2009) $
 */
public final class XssConfiguration {
	
	private static String DEFAULT_CONFIG = "/lucy-xss-default.xml";

	private Map<String, ElementRule> tags;
	private Map<String, AttributeRule> atts;
	private Map<String, Set<String>> tagGroups;
	private Map<String, Set<String>> attGroups;
	
	private XssConfiguration() {
		this.tags = new HashMap<String, ElementRule>();
		this.atts = new HashMap<String, AttributeRule>();
		this.tagGroups = new HashMap<String, Set<String>>();
		this.attGroups = new HashMap<String, Set<String>>();
	}

	/**
	 * 이 메소드는 특정 파일로부터 XSS Filter 설정 내용을 로딩하여, 새로운 인스턴스를 리턴한다.
	 * 
	 * @param file	XSS Filter 설정파일.
	 * @return	XssConfiguration 인스턴스.
	 * @throws Exception	설정 내용을 담고 있는 파일이 예상치 못한 포멧을 가지고 있을 경우 발생.
	 */
	public static XssConfiguration newInstance(String file) throws Exception {
		XssConfiguration config = null;
		
		InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(file);
		if (is == null) {
			is = XssConfiguration.class.getResourceAsStream(DEFAULT_CONFIG);
		}
		
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();		
			
			config = create(builder, is);
			
			if (config == null) {
				throw new Exception(String.format("The XSS configuration file [%s] is not a expected xml document.", file));
			}
		} catch(Exception ex) {
			throw new Exception(String.format("Cannot parse the XSS configuration file [%s].", file), ex);
		}
		
		return config;
	}
	
	private static XssConfiguration create(DocumentBuilder builder, InputStream is) {
		XssConfiguration config = null;
		
		try {
			Element root = builder.parse(is).getDocumentElement();
			String extend = root.getAttribute("extends");
			if (extend != null && !"".equals(extend)) {
				InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(extend);
				config = create(builder, stream);
			}
			
			if (config == null) {
				config = new XssConfiguration();
			}
			
			NodeList list = root.getElementsByTagName("elementGroup");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.addElementGroup(Element.class.cast(list.item(i)));
			}
			
			list = root.getElementsByTagName("attributeGroup");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.addAttributeGroup(Element.class.cast(list.item(i)));
			}
			
			list = root.getElementsByTagName("element");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.addElementRule(Element.class.cast(list.item(i)));
			}
			
			list = root.getElementsByTagName("attribute");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.addAttributeRule(Element.class.cast(list.item(i)));
			}
			
		} catch(Exception ex) {
			return null;
		} finally {
			if (is != null) {
				try { is.close(); } catch(IOException ioe) {}
			}
		}
		
		return config;
	}

	public ElementRule getElementRule(String tagName) {
		ElementRule rule = null;
		if (tagName != null && this.tags != null && !this.tags.isEmpty()) {
			rule = this.tags.get(tagName.toLowerCase());			
		}
		
		return rule;
	}

	public AttributeRule getAttributeRule(String attName) {
		AttributeRule rule = null;
		if (attName != null && this.atts != null && !this.atts.isEmpty()) {
			rule = this.atts.get(attName.toLowerCase());
		}
		
		return rule;
	}
	
	private void addElementRule(Element e) {
		String name = e.getAttribute("name");		
		boolean override = !"false".equalsIgnoreCase(e.getAttribute("override"));
		String endTag = e.getAttribute("endTag");
		String disable = e.getAttribute("disable");
		
		if (name == null || "".equals(name)) {
			return ;
		}
		
		ElementRule rule = null;
		if (override) {
			rule = this.tags.get(name);	
		}
		
		if (rule == null || !override) {
			rule = new ElementRule(name);
			this.tags.put(name.toLowerCase(), rule);
		}
		
		if (endTag != null && ("true".equalsIgnoreCase(endTag) || "false".equalsIgnoreCase(endTag))) {
			rule.setEndTag("true".equalsIgnoreCase(endTag)? true : false);
		}
		
		if (disable != null && ("true".equalsIgnoreCase(disable) || "false".equalsIgnoreCase(disable))) {
			rule.setDisabled("true".equalsIgnoreCase(disable)? true : false);
		}
		
		NodeList list = e.getElementsByTagName("attributes");
		if (list != null && list.getLength() > 0) {
			Element attributes = Element.class.cast(list.item(0));
			
			list = attributes.getChildNodes();
			rule.addAllowedAttributes(this.getReferences(list, this.attGroups));
		}
		
		list = e.getElementsByTagName("elements");
		if (list != null && list.getLength() > 0) {
			Element elements = Element.class.cast(list.item(0));
			
			list = elements.getChildNodes();
			rule.addAllowedElements(this.getReferences(list, this.tagGroups));
		}
		
		list = e.getElementsByTagName("listener");
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			String className = list.item(i).getTextContent();
			if (className != null) {
				try {
					Object obj = Class.forName(className.trim()).newInstance();
					rule.addListener(ElementListener.class.cast(obj));
				} catch(Exception ex) {
					// ignore
				}
			}
		}
	}
	
	private void addAttributeRule(Element e) {
		String name = e.getAttribute("name");
		boolean override = !"false".equalsIgnoreCase(e.getAttribute("override"));
		String disable = e.getAttribute("disable");
		
		if (name == null || "".equals(name)) {
			return ;
		}
		
		AttributeRule rule = null;
		if (override) {
			rule = this.atts.get(name);
		}
		
		if (rule == null || !override) {
			rule = new AttributeRule(name);
			this.atts.put(name.toLowerCase(), rule);
		}
		
		if (disable != null && ("true".equalsIgnoreCase(disable) || "false".equalsIgnoreCase(disable))) {
			rule.setDisabled("true".equalsIgnoreCase(disable)? true : false);
		}
		
		NodeList list = e.getElementsByTagName("allowedPattern");
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			rule.addAllowedPattern(list.item(i).getTextContent());
		}
		
		list = e.getElementsByTagName("notAllowedPattern");
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			rule.addNotAllowedPattern(list.item(i).getTextContent());
		}
	}
	
	private void addElementGroup(Element e) {
		String name = e.getAttribute("name");
		
		if (name == null || "".equals(name)) {
			return ;
		}
		
		Set<String> tagGroup = new HashSet<String>();		

		NodeList list = e.getElementsByTagName("ref");
		Collection<String> refs = this.getReferences(list, this.tagGroups);		
		if (refs != null && !refs.isEmpty()) {
			tagGroup.addAll(refs);
		}

		this.tagGroups.put(name, tagGroup);
	}
	
	private void addAttributeGroup(Element e) {
		String name = e.getAttribute("name");
		
		if (name == null || "".equals(name)) {
			return ;
		}
		
		Set<String> attGroup = new HashSet<String>();
		
		NodeList list = e.getElementsByTagName("ref");
		Collection<String> refs = this.getReferences(list, this.attGroups);
		if (refs != null && !refs.isEmpty()) {
			attGroup.addAll(refs);
		}

		this.attGroups.put(name, attGroup);
	}
	
	private Collection<String> getReferences(NodeList list, Map<String, Set<String>> groups) {
		Collection<String> result = new ArrayList<String>();
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			Node node = list.item(i);
			if (!(node.getNodeType() == Node.ELEMENT_NODE && node.getNodeName().equals("ref"))) {
				continue;
			}
			
			Element ref = Element.class.cast(node);
			String name = ref.getAttribute("name");
			if (groups.containsKey(name)) {
				Set<String> names = new HashSet<String>(groups.get(name));				
				NodeList excludes = ref.getElementsByTagName("excludes");
				if (excludes != null && excludes.getLength() > 0) {					
					Collection<String> tmp = this.getReferences(
							Element.class.cast(excludes.item(0)).getElementsByTagName("ref"), groups);
					if (tmp != null && !tmp.isEmpty()) {
						names.removeAll(tmp);
					}
				}

				if (!names.isEmpty()) {
					result.addAll(names);
				}				
			} else {
				result.add(name);
			}
		}
		
		return result;
	}
}
