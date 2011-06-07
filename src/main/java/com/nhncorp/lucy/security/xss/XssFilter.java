/*
 * @(#) XssFilter.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.nhncorp.lucy.security.xss.config.AttributeRule;
import com.nhncorp.lucy.security.xss.config.ElementRule;
import com.nhncorp.lucy.security.xss.config.XssConfiguration;
import com.nhncorp.lucy.security.xss.markup.Attribute;
import com.nhncorp.lucy.security.xss.markup.Comment;
import com.nhncorp.lucy.security.xss.markup.Content;
import com.nhncorp.lucy.security.xss.markup.Element;
import com.nhncorp.lucy.security.xss.markup.MarkupParser;
import com.nhncorp.lucy.security.xss.markup.Text;

/**
 * 이 클래스는 {@code Cross Site Scripting} 코드가 삽입된 {@code String} 데이터를 신뢰할 수 있는 코드로
 * 변환 시키거나, 삭제하는 기능을 제공한다. <br/><br/> 이 클래스를 사용하는 방법은 다음과 같다.
 * 
 * <pre>
 * ...
 * 
 * // XSS 설정파일(&quot;lucy-xss.xml&quot;)이 잘못된 포멧을 가지고 있다면 RuntimeException을 발생 시킨다.
 * XssFilter filter = XssFilter.getInstance();
 * 
 * String clean = filter.doFilter(String dirty);
 * 
 * ...
 * </pre>
 * 
 * @author Web Platform Development Team
 * 
 */
public final class XssFilter {

	private static String BAD_TAG_INFO = "<!-- Not Allowed Tag Filtered -->";
	private static String BAD_ATT_INFO = "<!-- Not Allowed Attribute Filtered -->";
	private static String CONFIG = "lucy-xss.xml";
	private boolean withoutComment;

	private XssConfiguration config;

	private static final Map<String, XssFilter> instanceMap = new HashMap<String, XssFilter>();

	private XssFilter(XssConfiguration config) {
		this.config = config;
	}

	/**
	 * 이 메소드는 XssFilter 객체를 리턴한다.
	 * 
	 * @return XssFilter 객체
	 * @throws XssFilterException
	 *             {@code "lucy-xss.xml"} 로딩 실패 시 발생(malformed인 경우).
	 */
	public static XssFilter getInstance() throws XssFilterException {
		return getInstance(CONFIG, false);
	}
	
	/**
	 * 이 메소드는 XssFilter 객체를 리턴한다.
	 * @param withoutComment
	 * 			   공격 패턴이 검출 됐을 때 알려주는 주석문의 추가 여부
	 * @return XssFilter 객체
	 * @throws XssFilterException
	 *             {@code "lucy-xss.xml"} 로딩 실패 시 발생(malformed인 경우).
	 */
	public static XssFilter getInstance(boolean withoutComment) throws XssFilterException {
		return getInstance(CONFIG, withoutComment);
	}
	
	/**
	 * 이 메소드는 XssFilter 객체를 리턴한다.
	 * 
	 * @param fileName
	 *            XSS Filter 설정파일
	 * @param withoutComment
	 * 			   공격 패턴이 검출 됐을 때 알려주는 주석문의 추가 여부
	 * @return XssFilter 객체
	 * @throws XssFilterException
	 *             설정파일 로딩 실패 시 발생(malformed인 경우).
	 */
	public static XssFilter getInstance(String fileName) throws XssFilterException {
		return getInstance(fileName, false);
	}

	/**
	 * 이 메소드는 XssFilter 객체를 리턴한다.
	 * 
	 * @param fileName
	 *            XSS Filter 설정파일
	 * @param withoutComment
	 * 			   공격 패턴이 검출 됐을 때 알려주는 주석문의 추가 여부
	 * @return XssFilter 객체
	 * @throws XssFilterException
	 *             설정파일 로딩 실패 시 발생(malformed인 경우).
	 */
	public static XssFilter getInstance(String fileName, boolean withoutComment) throws XssFilterException {
		XssFilter filter = instanceMap.get(fileName);
		if (filter != null) {
			filter.withoutComment = withoutComment;
			return filter;
		}
		try {
			synchronized (XssFilter.class) {
				filter = instanceMap.get(fileName);
				if (filter != null) {
					filter.withoutComment = withoutComment;
					return filter;
				}
				filter = new XssFilter(XssConfiguration.newInstance(fileName));
				filter.withoutComment = withoutComment;
				instanceMap.put(fileName, filter);
				return filter;
			}
		} catch (Exception e) {
			throw new XssFilterException(e.getMessage());
		}
	}

	/**
	 * 이 메소드는 XSS Filter 설정 내용을 담고 있는 {@link XssConfiguration} 객체를 반환한다.
	 * 
	 * @return {@link XssConfiguration} 객체
	 */
	public XssConfiguration getConfig() {
		return this.config;
	}

	/**
	 * 이 메소드는 XSS({@code Cross Site Scripting})이 포함된 위험한 코드에 대하여 신뢰할 수 있는 코드로
	 * 변환하거나, 삭제하는 기능을 제공한다. <br/> {@code "lucy-xss.xml"} 설정에 따라 필터링을 수행한다.
	 * 
	 * @param dirty
	 *            XSS({@code Cross Site Scripting})이 포함된 위험한 코드.
	 * @return 신뢰할 수 있는 코드.
	 */
	public String doFilter(String dirty) {
		if (dirty == null || "".equals(dirty)) {
			return "";
		}

		String result = "";
		Collection<Content> contents = MarkupParser.parse(dirty);

		if (contents != null && !contents.isEmpty()) {
			StringWriter writer = new StringWriter();
			try {
				this.serialize(writer, contents);
			} catch (IOException ioe) {
			}
			result = writer.toString();
		}

		return result;
	}

	/**
	 * 이 메소드는 특정 Tag 내 특정 Attribute의 값에 삽입되는 XSS({@code Cross Site Scripting})이
	 * 포함된 위험한 코드를 신뢰할 수 있는 코드로 변환하거나, 삭제하는 기능을 제공한다. <br/>
	 * {@code "lucy-xss.xml"} 설정에 따라 필터링을 수행한다.
	 * 
	 * @param tagName
	 *            특정 Tag 이름.
	 * @param attName
	 *            특정 Attribute 이름.
	 * @param dirtyAttValue
	 *            XSS({@code Cross Site Scripting})이 포함된 위험한 Attribute 값.
	 * @return
	 */
	public String doFilter(String tagName, String attName, String dirtyAttValue) {
		if (tagName == null || "".equals(tagName) || attName == null || "".equals(attName)
				|| dirtyAttValue == null || "".equals(dirtyAttValue)) {
			return "";
		}

		StringBuffer dirty = new StringBuffer();
		dirty.append('<').append(tagName);
		dirty.append(' ').append(attName).append('=').append(dirtyAttValue);
		dirty.append('>').append("</").append(tagName).append('>');

		Collection<Content> contents = MarkupParser.parse(dirty.toString());
		if (contents != null && !contents.isEmpty()) {
			for (Content c : contents) {
				if (c instanceof Element) {
					Element tag = Element.class.cast(c);
					this.checkRule(tag);

					Attribute att = tag.getAttribute(attName);
					if (att.isDisabled()) {
						return "";
					} else {
						return att.getValue();
					}
				}
			}
		}

		return "";
	}

	private void serialize(Writer writer, Collection<Content> contents) throws IOException {
		if (contents != null && !contents.isEmpty()) {
			for (Content c : contents) {
				if (c instanceof Comment || c instanceof Text) {
					c.serialize(writer);
				} else if (c instanceof Element) {
					this.serialize(writer, Element.class.cast(c));
				}
			}
		}
	}

	private void serialize(Writer writer, Element e) throws IOException {
		if (!e.isDisabled()) {
			checkRule(e);
		}

		if (e.isDisabled()) {
			
			if (!this.withoutComment) {
			
				writer.write(BAD_TAG_INFO);
			}
			
			writer.write("&lt;");
			writer.write(e.getName());
		} else if (e.existDisabledAttribute()) {
			
			if (!this.withoutComment) {
			
				writer.write(BAD_ATT_INFO);
			}
			
			writer.write('<');
			writer.write(e.getName());
		} else {
			writer.write('<');
			writer.write(e.getName());
		}

		Collection<Attribute> atts = e.getAttributes();
		if (atts != null && !atts.isEmpty()) {
			for (Attribute att : atts) {
				if (!e.isDisabled() && att.isDisabled()) {
					continue;
				} else {
					writer.write(' ');
					att.serialize(writer);
				}
			}
		}

		if(e.isStartClosed()) {

			writer.write((e.isDisabled()) ? " /&gt;" : " />");

		} else {
	
			writer.write((e.isDisabled()) ? "&gt;" : ">");
		}

		if (!e.isEmpty()) {
			this.serialize(writer, e.getContents());
		}

		if (e.isClosed()) {
			if (e.isDisabled()) {
				writer.write("&lt;/");
				writer.write(e.getName());
				writer.write("&gt;");
			} else {
				writer.write("</");
				writer.write(e.getName());
				writer.write('>');
			}
		}
	}

	private void checkRule(Element e) {
		ElementRule tagRule = this.config.getElementRule(e.getName());
		if (tagRule == null) {
			e.setEnabled(false);
			return;
		}

		tagRule.checkEndTag(e);
		tagRule.checkDisabled(e);
		tagRule.disableNotAllowedAttributes(e);
		tagRule.disableNotAllowedChildElements(e);

		Collection<Attribute> atts = e.getAttributes();
		if (atts != null && !atts.isEmpty()) {
			for (Attribute att : atts) {
				if (att.isDisabled() || att.isMinimized()) {
					continue;
				}
				AttributeRule attRule = this.config.getAttributeRule(att.getName());
				if (attRule == null) {
					att.setEnabled(false);
				} else {
					attRule.checkDisabled(att);
					attRule.checkAttributeValue(att);
				}
			}
		}

		tagRule.excuteListener(e);
	}
}
