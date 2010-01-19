package com.nhncorp.lucy.security.xss.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Attribute;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 18530 $, $Date: 2008-08-14 14:41:03 +0900 (목, 14 8 2008) $
 */
public final class ElementRule {

	private String name;
	private boolean endTag;
	private boolean disabled;
	private Set<String> atts;
	private Set<String> tags;
	private List<ElementListener> listeners;
	
	ElementRule(String name) {
		this.name = name;
		this.atts = new HashSet<String>();
		this.tags = new HashSet<String>();
	}

	public String getName() {
		return (this.name == null)? "" : this.name;
	}
	
	public boolean hasEndTag() {
		return this.endTag;
	}
	
	public boolean isDisabled() {
		return this.disabled;
	}
	
	public Set<String> getAllowedAttributes() {
		return Collections.unmodifiableSet(this.atts);
	}
	
	public Set<String> getAllowedElements() {
		return Collections.unmodifiableSet(this.tags);
	}
	
	public List<ElementListener> getListeners() {
		return Collections.unmodifiableList(this.listeners);
	}

	public void checkEndTag(Element e) {
		if (e == null) {
			return ;
		} 
		
		if (this.endTag && !e.isClosed()) {
			e.setEnabled(false);
		}
	}

	public void checkDisabled(Element e) {
		if (this.disabled) {
			e.setEnabled(false);
		}
	}

	public void disableNotAllowedAttributes(Element e) {
		Collection<Attribute> atts = e.getAttributes();
		if (atts != null && !atts.isEmpty()) {
			for (Attribute att : atts) {
				if (!this.atts.contains(att.getName().toLowerCase())) {
					att.setEnabled(false);
				}
			}
		}
	}

	public void disableNotAllowedChildElements(Element e) {
		List<Element> tags = e.getElements();
		if (tags != null && !tags.isEmpty()) {
			for (Element tag : tags) {				
				if (!this.tags.contains(tag.getName().toLowerCase())) {
					tag.setEnabled(false);
				}
			}
		}
	}

	public void excuteListener(Element e) {
		if (this.listeners != null && !this.listeners.isEmpty()) {
			for (ElementListener l : this.listeners) {
				l.handleElement(e);
			}
		}
	}
	
	void setEndTag(boolean isRequired) {
		this.endTag = isRequired;
	}
	
	boolean getEndTagFlag() {
		return this.endTag;
	}
	
	void setDisabled(boolean disabled) {
		this.disabled = disabled;
	}
	
	boolean getDisabledFlag() {
		return this.disabled;
	}
	
	void addAllowedAttribute(String attName) {
		if (attName != null) {
			this.atts.add(attName.toLowerCase());
		}
	}
	
	void addAllowedAttributes(Collection<String> attNames) {
		if (attNames != null && !attNames.isEmpty()) {
			for (String attName : attNames) {
				this.addAllowedAttribute(attName);
			}
		}
	}
	
	void addAllowedElement(String tagName) {
		if (tagName != null) {
			this.tags.add(tagName.toLowerCase());
		}
	}
	
	void addAllowedElements(Collection<String> tagNames) {
		if (tagNames != null && !tagNames.isEmpty()) {
			for (String tagName : tagNames) {
				this.addAllowedElement(tagName);
			}
		}
	}
	
	void addListener(ElementListener l) {
		if (l != null) {
			if (this.listeners == null) {
				this.listeners = new ArrayList<ElementListener>();
			}
			
			this.listeners.add(l);
		}
	}
}
