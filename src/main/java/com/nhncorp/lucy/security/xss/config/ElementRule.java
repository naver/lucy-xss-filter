/*
 * @(#) ElementRule.java 2010. 8. 11
 *
 * Copyright 2010 NHN Corp. All rights Reserved.
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
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
import com.nhncorp.lucy.security.xss.markup.IEHackExtensionElement;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * 
 * @author Naver Labs
 * 
 */
public final class ElementRule {
	private String name;
	private boolean endTag;
	private boolean disabled;
	private boolean removeTag = false;
	private Set<String> atts;
	private Set<String> tags;
	private List<ElementListener> listeners;

	public ElementRule(String name) {
		this.name = name;
		this.atts = new HashSet<String>();
		this.tags = new HashSet<String>();
	}

	public String getName() {
		return (this.name == null) ? "" : this.name;
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

	public void checkEndTag(Element element) {
		if (element == null) {
			return;
		}

		if (this.endTag && !element.isClosed()) {
			element.setEnabled(false);
		}
	}

	public void checkDisabled(Element element) {
		if (this.disabled) {
			element.setEnabled(false);
		}
	}

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

	public void disableNotAllowedChildElements(Element element) {
		List<Element> tags = element.getElements();
		if (tags != null && !tags.isEmpty()) {
			for (Element tag : tags) {
				if (!this.tags.contains(tag.getName().toLowerCase())) {
					if (!(tag instanceof IEHackExtensionElement)) {
						tag.setEnabled(false);
					}
				}
			}
		}
	}

	public void excuteListener(Element element) {
		if (this.listeners != null && !this.listeners.isEmpty()) {
			for (ElementListener listener : this.listeners) {
				listener.handleElement(element);
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

	void addListener(ElementListener listener) {
		if (listener != null) {
			if (this.listeners == null) {
				this.listeners = new ArrayList<ElementListener>();
			}

			this.listeners.add(listener);
		}
	}

	public boolean isRemoveTag() {
		return removeTag;
	}

	public void setRemoveTag(boolean removeTag) {
		this.removeTag = removeTag;
	}

	public void checkRemoveTag(Element element) {
		if (element == null) {
			return;
		}

		element.setRemoved(this.removeTag);
	}
}
