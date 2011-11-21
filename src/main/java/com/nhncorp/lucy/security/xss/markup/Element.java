/*
 * @(#) Element.java 2010. 8. 11
 *
 * Copyright 2010 NHN Corp. All rights Reserved.
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 이 클래스는 하나의 Tag 를 나타낸다.
 * 하나의 Tag 는 Tag Name과 {@link Attribute Attribute} 들을 포함을 하며,
 * 또한 하위에 {@link Content Content} 들을 포함할 수 있다.
 *
 * @author Web Platform Development Team
 *
 */
public class Element extends Content {

	/**
	 * 이 멤버 변수는 Tag 이름을 저장한다.
	 */
	protected String name;
	/**
	 * 이 멤버 변수는 {@link Attribute Attribute} 들을 {@code Map} 형태로 저장을 하며,
	 * Key 값은 Attribute Name 의 소문자가 된다.
	 */
	protected Map<String, Attribute> atts;
	/**
	 * 이 멤버 변수는 하위 {@link Content Content} 들을 저장한다.
	 */
	protected List<Content> contents;
	/**
	 * 이 멤버 변수는 Tag가 닫혀 있는지 여부를 저장한다. (기본값은 {@code false}).
	 */
	protected boolean isClosed;

	/**
	 * 이 멤버 변수는 Tag가 Start Tag에서 닫혀 있는지 여부를 저장한다. (기본값은 {@code false}).
	 */
	protected boolean isStartClosed;

	/**
	 * {@link com.nhncorp.lucy.security.xss.XssFilter XssCleaner}에서 사용하는 멤버 변수로
	 * Attribute 의 활성화 여부를 나타낸다.
	 * 기본값은 {@code true}.
	 */
	protected boolean enabled = true;

	/**
	 * {@link com.nhncorp.lucy.security.xss.XssFilter doFilter} 메소드에서의
	 * Element의 삭제여부를 결정한다.
	 */
	protected boolean removed = false;

	/**
	 * Tag Name 으로 초기화하는 생성자.
	 *
	 * @param name	Tag Name.
	 */
	public Element(String name) {
		this.name = name;
	}

	/**
	 * 이 메소드는 Tag Name 을 리턴한다. 만약 Tag Name 이 널이면, ""을 반환한다.
	 *
	 * @return	Tag Name.
	 */
	public String getName() {
		return (this.name == null) ? "" : this.name;
	}

	public void setName(String name) {
		this.name = name;
	}

	/**
	 * 이 메소드는 Tag 가 닫혀 있는지 여부를 리턴한다.
	 *
	 * @return	닫혀 있으면 {@code true}, 그렇지 않으면 {@code false}.
	 */
	public boolean isClosed() {
		return this.isClosed;
	}

	/**
	 * 이 메소드는 Tag 가 닫혀 있는지 여부를 세팅한다.
	 *
	 * @param close	Tag 가 닫혀 있는지 여부.
	 */
	public void setClose(boolean close) {
		this.isClosed = close;
	}

	/**
	 * 이 메소드는 Tag 가 닫혀 있는지 여부를 리턴한다.
	 *
	 * @return	닫혀 있으면 {@code true}, 그렇지 않으면 {@code false}.
	 */
	public boolean isStartClosed() {
		return this.isStartClosed;
	}

	/**
	 * 이 메소드는 Tag 가 닫혀 있는지 여부를 세팅한다.
	 *
	 * @param close	Tag 가 닫혀 있는지 여부.
	 */
	public void setStartClose(boolean startClose) {
		this.isStartClosed = startClose;
	}

	/**
	 * 이 메소드는 하나의 Attribute 를 이름과 값으로 추가한다. attValue 에 인용부호가 필요하다면 추가해야 한다.
	 *
	 * @param attName	Attribute Name.
	 * @param attValue	Attribute Value.
	 */
	public void putAttribute(String attName, String attValue) {
		if (this.atts == null) {
			this.atts = new LinkedHashMap<String, Attribute>();
		}

		this.atts.put(attName.toLowerCase(), new Attribute(attName, attValue));
	}

	/**
	 * 이 메소드는 하나의 {@link Attribute Attribute} 를 추가한다.
	 *
	 * @param att	Attribute.
	 */
	public void putAttribute(Attribute att) {
		if (att == null) {
			return;
		}

		if (this.atts == null) {
			this.atts = new LinkedHashMap<String, Attribute>();
		}

		this.atts.put(att.getName().toLowerCase(), att);
	}

	/**
	 * 이 메소드는 attName 에 해당하는 {@link Attribute Attribute} 를 리턴한다.
	 *
	 * @param attName	Attribute Name.
	 * @return	{@link Attribute Attribute}, 없으면 null.
	 */
	public Attribute getAttribute(String attName) {
		if (this.atts == null || attName == null) {
			return null;
		}

		return this.atts.get(attName.toLowerCase());
	}

	/**
	 * 이 메소드는 attName 에 해당하는 {@link Attribute Attribute} 값을 리턴한다.
	 *
	 * @param attName	Attribute Name.
	 * @return	{@link Attribute Attribute} 값, 없으면 "".
	 */
	public String getAttributeValue(String attName) {
		if (this.atts == null || attName == null) {
			return "";
		}

		String value = "";
		Attribute att = this.atts.get(attName.toLowerCase());
		if (att != null) {
			value = att.getValue();
		}
		return value;
	}

	/**
	 * 이 메소드는 모든 {@link Attribute Attribute} 들을 {@code Collection} 으로 리턴한다.
	 *
	 * @return	{@link Attribute Attribute} {@code Collection}.
	 */
	public Collection<Attribute> getAttributes() {
		if (this.atts == null) {
			return null;
		}

		return this.atts.values();
	}

	/**
	 * 이 메소드는 하위에 {@link Content Content} 를 포함하고 있는지 여부를 리턴한다.
	 *
	 * @return	하위 {@link Content Content} 가 있으면 {@code true}, 그렇지 않으면 {@code false}.
	 */
	public boolean isEmpty() {
		if (this.contents != null && !this.contents.isEmpty()) {
			return false;
		}

		return true;
	}

	/**
	 * 이 메소드는 하위에 있는 모든 {@link Content Content} 들을 {@code List} 로 리턴한다.
	 *
	 * @return	{@link Content Content} {@code List}.
	 */
	public List<Content> getContents() {
		return (this.isEmpty()) ? null : this.contents;
	}

	/**
	 * 이 메소드는 하위에 있는 모든 {@link Element Element} 들을 {@code List} 로 리턴한다.
	 *
	 * @return	{@link Element Element} {@code List}.
	 */
	public List<Element> getElements() {
		if (this.isEmpty()) {
			return null;
		}

		List<Element> elements = new ArrayList<Element>();
		for (Content c : this.contents) {
			if (c instanceof Element) {
				elements.add(Element.class.cast(c));
			}
		}

		return elements;
	}

	/**
	 * 이 메소드는 특정 {@link Content Content} 의 Index 를 리턴한다.
	 *
	 * @param content	{@link Content Content}.
	 * @return	Index 값, 없으면 -1.
	 */
	public int indexOf(Content content) {
		if (this.isEmpty()) {
			return -1;
		}

		return this.contents.indexOf(content);
	}

	/**
	 * 이 메소드는 하위에 {@link Content Content} 을 추가한다.
	 *
	 * @param content	추가할 {@link Content Content}.
	 */
	public void addContent(Content content) {
		if (content == null) {
			return;
		}

		content.setParent(this);
		if (this.contents == null) {
			this.contents = new ArrayList<Content>();
		}

		this.contents.add(content);
	}

	/**
	 * 이 메소드는 하위에 {@link Content Content} 을 특정 Index 에 추가한다.
	 *
	 * @param index	추가 할 Index 값.
	 * @param content	추가할 {@link Content Content}.
	 * @throws IndexOutOfBoundsException	Index 값이 해당 범위를 벗어 날때 발생.
	 */
	public void addContent(int index, Content content) {
		if (content == null) {
			return;
		}

		content.setParent(this);
		if (this.contents == null) {
			this.contents = new ArrayList<Content>();
		}

		this.contents.add(index, content);
	}

	/**
	 * 이 메소드는 하위에 {@link Content Content} 을 특정 Index 에 대체시킨다.
	 *
	 * @param index	대체 할 Index 값.
	 * @param content	대체 할 {@link Content Content}.
	 * @throws IndexOutOfBoundsException	Index 값이 해당 범위를 벗어 날때 발생.
	 */
	public void setContent(int index, Content content) {
		if (content == null) {
			return;
		}

		content.setParent(this);
		if (this.contents == null) {
			this.contents = new ArrayList<Content>();
		}

		this.contents.set(index, content);
	}

	/**
	 * 이 메소드는 특정 {@link Content Content} 의 {@code Collection} 을 추가 한다.
	 *
	 * @param contents	추가 할 {@link Content Content} {@code Collection}.
	 */
	public void addContents(Collection<? extends Content> contents) {
		if (contents == null) {
			return;
		}

		for (Content c : contents) {
			this.addContent(c);
		}
	}

	/**
	 * 이 메소드는 하위에 있는 특정 {@link Content Content} 를 삭제 한다.
	 *
	 * @param content	삭제 할 {@link Content Content}.
	 */
	public void removeContent(Content content) {
		if (content != null && !this.isEmpty()) {
			this.contents.remove(content);
		}
	}

	/**
	 * 이 메소드는 하위에 있는 특정 Index 의 {@link Content Content} 를 삭제 한다.
	 *
	 * @param index	삭제 대상 {@link Content Content} 의 Index 값.
	 * @throws IndexOutOfBoundsException	Index 값이 해당 범위를 벗어 날때 발생.
	 */
	public void removeContent(int index) {
		if (!this.isEmpty()) {
			this.contents.remove(index);
		}
	}

	/**
	 * 이 메소드는 {@code 'ID(or id)'} 를 이름으로 갖는 Attribute 가 존재 하는 모든 하위
	 * 태그들에 대하여 id 값이 일치하는 {@link Element Element} 를 리턴한다.
	 *
	 * @param id	id 값.
	 * @return	id 값이 일치하는 {@link Element Element}.
	 */
	public Element getElementById(String id) {
		if (id == null || this.isEmpty()) {
			return null;
		}

		Element result = null;
		for (Content c : this.contents) {
			if (c instanceof Element) {
				Element e = Element.class.cast(c);
				if (id.equals(e.getAttributeValue("id"))) {
					result = e;
				} else {
					result = e.getElementById(id);
				}

				if (result != null) {
					break;
				}
			}
		}

		return result;
	}

	/**
	 * 이 메소드는 특정 Tag Name 과 일치하는 하위 태그들의 {@code List} 를 리턴한다.
	 *
	 * @param tagName	Tag Name.
	 * @return	Tag Name 과 일치하는 하위 태그들의 {@code List}.
	 */
	public List<Element> getElementsByTagName(String tagName) {
		if (tagName == null || this.isEmpty()) {
			return null;
		}

		List<Element> result = new ArrayList<Element>();
		for (Content c : this.contents) {
			if (c instanceof Element) {
				Element e = Element.class.cast(c);
				if (e.getName().equalsIgnoreCase(tagName)) {
					result.add(e);
				}

				if (!e.isEmpty()) {
					result.addAll(e.getElementsByTagName(tagName));
				}
			}
		}

		return result;
	}

	public void serialize(Writer writer) throws IOException {
		if (writer == null) {
			return;
		}

		writer.write('<');
		writer.write(this.getName());

		if (this.atts != null && !this.atts.isEmpty()) {
			for (Attribute att : this.atts.values()) {
				writer.write(' ');
				att.serialize(writer);
			}
		}
		writer.write('>');

		if (!this.isEmpty()) {
			for (Content c : this.contents) {
				c.serialize(writer);
			}
		}

		if (this.isClosed) {
			writer.write("</");
			writer.write(this.getName());
			writer.write('>');
		}
	}

	/**
	 * 이 메소드는 {@link Element Element} 가 비활성 되어 있는지 여부를 리턴한다.
	 * {@link com.nhncorp.lucy.security.xss.XssFilter XssCleaner}에서 사용.
	 *
	 * @return	{@link Element Element} 의 비활성 여부.
	 */
	public boolean isDisabled() {
		return !this.enabled;
	}

	/**
	 * 이 메소드는 {@link Element Element} 를 활성 또는 비활성 시킨다.
	 *
	 * @param flag	{@code true}이면 활성, {@code false}이면 비활성.
	 */
	public void setEnabled(boolean flag) {
		this.enabled = flag;
	}

	/**
	 * 이 메소드는 비활성화 된  {@link Attribute Attribute} 가 존재하는지 여부를 리턴한다.
	 *
	 * @return	비활성화 된  {@link Attribute Attribute} 가 존재하면 {@code true}, 그렇지 않으면 {@code false}.
	 */
	public boolean existDisabledAttribute() {
		boolean flag = false;
		Collection<Attribute> atts = this.getAttributes();
		if (atts != null && !atts.isEmpty()) {
			for (Attribute att : atts) {
				if (att.isDisabled()) {
					flag = true;
					break;
				}
			}
		}

		return flag;
	}

	public boolean removeAllAttributes() {

		if (this.atts != null && !this.atts.isEmpty()) {

			this.atts.clear();

			return true;
		}

		return false;
	}

	public Attribute removeAttribute(String attriName) {

		return this.atts.remove(attriName);
	}

	public boolean removeAllContents() {

		if (this.contents != null && !this.contents.isEmpty()) {

			this.contents.clear();

			return true;
		}

		return false;
	}

	public boolean isRemoved() {
		return removed;
	}

	public void setRemoved(boolean removed) {
		this.removed = removed;
	}
}
