/*
 * @(#) XssConfiguration.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
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
 * 
 */
public final class XssConfiguration {
	
	private static String DEFAULT_CONFIG = "/lucy-xss-default.xml";

	private Map<String, ElementRule> tags;
	private Map<String, AttributeRule> atts;
	private Map<String, Set<String>> tagGroups;
	private Map<String, Set<String>> attGroups;
	private boolean neloAsyncLog;
	private String service = "UnknownService";
	private boolean isBlockingPrefixEnabled;
	private String blockingPrefix = "diabled_";

	private Map<String, Set<String>> elementGroupRef;
	private Map<String, Set<String>> nestedElementGroupRef;
	
	
	private XssConfiguration() {
		this.tags = new HashMap<String, ElementRule>();
		this.atts = new HashMap<String, AttributeRule>();
		this.tagGroups = new HashMap<String, Set<String>>();
		this.attGroups = new HashMap<String, Set<String>>();
		this.elementGroupRef = new HashMap<String, Set<String>>();
		this.nestedElementGroupRef = new HashMap<String, Set<String>>();
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
		
//		InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(file);
//		if (is == null) {
//			is = XssConfiguration.class.getResourceAsStream(DEFAULT_CONFIG);
//		}
		
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();		
			
			config = create(builder, file);
			
			if (config == null) {
				throw new Exception(String.format("The XSS configuration file [%s] is not a expected xml document.", file));
			}
		} catch(Exception ex) {
			throw new Exception(String.format("Cannot parse the XSS configuration file [%s].", file), ex);
		}
		
		config.closeElementGroupRefResource();
		config.closeNestedElementGroupRefResource();
		return config;
	}
	
	private static XssConfiguration create(DocumentBuilder builder, String file) {
		XssConfiguration config = null;
		
		InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(file);
		if (is == null) {
			is = XssConfiguration.class.getResourceAsStream(DEFAULT_CONFIG);
		}
		
		try {
			Element root = builder.parse(is).getDocumentElement();
			String extend = root.getAttribute("extends");
			if (extend != null && !"".equals(extend)) {
				//InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(extend);
				config = create(builder, extend);
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
			
			list = root.getElementsByTagName("neloAsyncLog");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.enableNeloAsyncLog(Element.class.cast(list.item(i)));
			}
			
			list = root.getElementsByTagName("blockingPrefix");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.enableBlockingPrefix(Element.class.cast(list.item(i)));
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

	private void enableBlockingPrefix(Element e) {
		String enable = e.getAttribute("enable");
		String prefix = e.getAttribute("prefix");
		
		if (enable != null && ("true".equalsIgnoreCase(enable) || "false".equalsIgnoreCase(enable))) {
			this.setBlockingPrefixEnabled("true".equalsIgnoreCase(enable)? true : false);
		}
		
		if (prefix != null && !prefix.isEmpty()) {
			this.setBlockingPrefix(prefix);
		}
		
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
	
	private void enableNeloAsyncLog(Element e) {
		String enable = e.getAttribute("enable");
		String serviceName = e.getAttribute("service");
		
		if (enable != null && ("true".equalsIgnoreCase(enable) || "false".equalsIgnoreCase(enable))) {
			this.setNeloAsyncLog("true".equalsIgnoreCase(enable)? true : false);
		}
		
		if (serviceName != null && !serviceName.isEmpty()) {
			this.setService(serviceName);
		} 
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
			rule.addAllowedAttributes(this.getReferences(list, this.attGroups, null));
		}
		
		list = e.getElementsByTagName("elements");
		if (list != null && list.getLength() > 0) {
			Element elements = Element.class.cast(list.item(0));
			
			list = elements.getChildNodes();
			System.out.println("AA" + name);
			this.addElementGroupRef(list, name);
			System.out.println("BB" + name);
			rule.addAllowedElements(this.getReferences(list, this.tagGroups, null));
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
	
	private void addAttributeRule(Element element) {
		String name = element.getAttribute("name");
		boolean override = !"false".equalsIgnoreCase(element.getAttribute("override"));
		String disable = element.getAttribute("disable");
		//Base64Decoding
		String base64Decoding = element.getAttribute("base64Decoding");
		
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
		
		//Base64Decoding
		if (base64Decoding != null && ("true".equalsIgnoreCase(base64Decoding) || "false".equalsIgnoreCase(base64Decoding))) {
			rule.setBase64Decoding("true".equalsIgnoreCase(base64Decoding) ? true : false);
		}
		
		NodeList list = element.getElementsByTagName("allowedPattern");
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			rule.addAllowedPattern(list.item(i).getTextContent());
		}
		
		list = element.getElementsByTagName("notAllowedPattern");
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			rule.addNotAllowedPattern(list.item(i).getTextContent());
		}
	}
	
	private void addElementGroup(Element e) {
		
		String name = e.getAttribute("name");
		boolean override = !"false".equalsIgnoreCase(e.getAttribute("override"));
		
		if (name == null || "".equals(name)) {
			return ;
		}
		
		Set<String> tagGroup = null;		

		if (override) {
			tagGroup = this.tagGroups.get(name);
		} 
		
		if (tagGroup == null) {
			tagGroup = new HashSet<String>();
		}
		

		NodeList list = e.getElementsByTagName("ref");
		Set<String> nestedGroups = new HashSet<String>();
		Collection<String> refs = this.getReferences(list, this.tagGroups, nestedGroups);		
		if (refs != null && !refs.isEmpty()) {
			tagGroup.addAll(refs);
		}
		
		if (nestedGroups != null && !nestedGroups.isEmpty()) {
			this.nestedElementGroupRef.put(name, nestedGroups);
		}

		this.tagGroups.put(name, tagGroup);

		if (override) {
			/**
			 * TO-DO : 
			 */
			Set<String> elementSet = elementGroupRef.get(name);
			if (elementSet != null) {
				for(String tagName : elementSet) {
					ElementRule rule = this.tags.get(tagName);
					rule.addAllowedElements(refs);
				}
			}
		}
	}
	
	private void addAttributeGroup(Element e) {
		String name = e.getAttribute("name");
		
		if (name == null || "".equals(name)) {
			return ;
		}
		
		Set<String> attGroup = new HashSet<String>();
		
		NodeList list = e.getElementsByTagName("ref");
		Collection<String> refs = this.getReferences(list, this.attGroups, null);
		if (refs != null && !refs.isEmpty()) {
			attGroup.addAll(refs);
		}

		this.attGroups.put(name, attGroup);
	}
	
	private void addElementGroupRef(NodeList list, String tagName) {
		
		for(int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			Node node = list.item(i);
			if (!(node.getNodeType() == Node.ELEMENT_NODE && node.getNodeName().equals("ref"))) {
				continue;
			}

			Element ref = Element.class.cast(node);
			String tagGroupName = ref.getAttribute("name");
			Set<String> nestedGroupNames = new HashSet<String>();

			if (this.tagGroups.containsKey(tagGroupName)) { //elementGroup name 이면,
				nestedGroupNames.add(tagGroupName);
				System.out.println(tagGroupName);
				Set<String> tagGroupSet = this.nestedElementGroupRef.get(tagGroupName);
				
				if (tagGroupSet != null) {
					nestedGroupNames.addAll(this.nestedElementGroupRef.get(tagGroupName));
				}
				
				for (String groupName : nestedGroupNames) {
					if (this.elementGroupRef.containsKey(groupName)) {
						Set<String> elementList = this.elementGroupRef.get(groupName);
						elementList.add(tagName);
					} else {
						Set<String> newElementSet = new HashSet<String>();
						newElementSet.add(tagName);
						this.elementGroupRef.put(groupName, newElementSet);
					}
				}
			}			
		}
		
	}
	

	private Collection<String> getReferences(NodeList list, Map<String, Set<String>> groups, Set<String> nestedGroups) {
		Collection<String> result = new ArrayList<String>();
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			Node node = list.item(i);
			if (!(node.getNodeType() == Node.ELEMENT_NODE && node.getNodeName().equals("ref"))) {
				continue;
			}
			
			Element ref = Element.class.cast(node);
			String name = ref.getAttribute("name");
			if (groups.containsKey(name)) {
				
				if (nestedGroups != null) {
					nestedGroups.add(name);
				}
				
				Set<String> names = new HashSet<String>(groups.get(name));				
				NodeList excludes = ref.getElementsByTagName("excludes");
				if (excludes != null && excludes.getLength() > 0) {					
					Collection<String> tmp = this.getReferences(
							Element.class.cast(excludes.item(0)).getElementsByTagName("ref"), groups, null);
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

	public void setNeloAsyncLog(boolean neloAsyncLog) {
		this.neloAsyncLog = neloAsyncLog;
	}

	public boolean enableNeloAsyncLog() {
		return neloAsyncLog;
	}

	public void setService(String service) {
		this.service = service;
	}

	public String getService() {
		return service;
	}

	public void setBlockingPrefixEnabled(boolean isEnableBlockingPrefix) {
	
		this.isBlockingPrefixEnabled = isEnableBlockingPrefix;
	}
	
	public boolean isEnableBlockingPrefix() {
		
		return this.isBlockingPrefixEnabled;
	}

	public void setBlockingPrefix(String blockingPrefix) {
		this.blockingPrefix = blockingPrefix;
	}

	public String getBlockingPrefix() {
		return blockingPrefix;
	}
	
	public void closeElementGroupRefResource() {
		this.elementGroupRef = null;
	}
	
	public void closeNestedElementGroupRefResource() {
		this.nestedElementGroupRef = null;
	}
}
