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
 * @version $Rev: 22185 $, $Date: 2009-08-27 10:31:41 +0900 (목, 27 8 2009) $
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
		return (this.name == null) ? "" : this.name;
	}

	/**
	 * 
	 * @return boolean
	 */
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

	/**
	 * 
	 * @return List
	 */
	public List<ElementListener> getListeners() {
		return Collections.unmodifiableList(this.listeners);
	}

	/**
	 * 
	 * @param element Element
	 */
	public void checkEndTag(Element element) {
		if (element == null) {
			return;
		}

		if (this.endTag && !element.isClosed()) {
			element.setEnabled(false);
		}
	}

	/**
	 * 
	 * @param element Element
	 */
	public void checkDisabled(Element element) {
		if (this.disabled) {
			element.setEnabled(false);
		}
	}

	/**
	 * 
	 * @param element Element
	 */
	public void disableNotAllowedAttributes(Element element) {
		Collection<Attribute> atts = element.getAttributes();
		
		if (atts != null && !atts.isEmpty()) {
			for (Attribute att : atts) {
				if (!this.atts.contains(att.getName().toLowerCase())) {
					
					att.setEnabled(false);
				}
			}
		}
	}

	/**
	 * 
	 * @param element Element
	 */
	public void disableNotAllowedChildElements(Element element) {
		List<Element> tags = element.getElements();
		
		if (tags != null && !tags.isEmpty()) {
			for (Element tag : tags) {
				if (!this.tags.contains(tag.getName().toLowerCase())) {
					tag.setEnabled(false);
				}
			}
		}
	}

	/**
	 * 
	 * @param element Element
	 */
	public void excuteListener(Element element) {
		if (this.listeners != null && !this.listeners.isEmpty()) {
			for (ElementListener elelistener : this.listeners) {
				elelistener.handleElement(element);
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

	/**
	 * 
	 * @param attName String
	 */
	void addAllowedAttribute(String attName) {
		if (attName != null) {
			this.atts.add(attName.toLowerCase());
		}
	}

	/**
	 * 
	 * @param attNames Collection
	 */
	void addAllowedAttributes(Collection<String> attNames) {
		if (attNames != null && !attNames.isEmpty()) {
			for (String attName : attNames) {
				this.addAllowedAttribute(attName);
			}
		}
	}

	/**
	 * 
	 * @param tagName String
	 */
	void addAllowedElement(String tagName) {
		if (tagName != null) {
			this.tags.add(tagName.toLowerCase());
		}
	}

	/**
	 * 
	 * @param tagNames Collection
	 */
	void addAllowedElements(Collection<String> tagNames) {
		if (tagNames != null && !tagNames.isEmpty()) {
			for (String tagName : tagNames) {
				this.addAllowedElement(tagName);
			}
		}
	}

	/**
	 * 
	 * @param eleListener ElementListener
	 */
	void addListener(ElementListener eleListener) {
		if (eleListener != null) {
			if (this.listeners == null) {
				this.listeners = new ArrayList<ElementListener>();
			}

			this.listeners.add(eleListener);
		}
	}
}
