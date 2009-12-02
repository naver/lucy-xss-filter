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
 * @version $Rev: 22445 $, $Date: 2009-09-24 11:06:40 +0900 (목, 24 9 2009) $
 */
public final class XssFilter {
	private static final String BAD_TAG_INFO = "<!-- Not Allowed Tag Filtered -->";
	private static final String BAD_ATT_INFO = "<!-- Not Allowed Attribute Filtered -->";
	private static final String CONFIG = "lucy-xss.xml";
	private XssConfiguration config;
	private static final Map<String, XssFilter> INSTANCE_MAP = new HashMap<String, XssFilter>();

	/**
	 * 생성자
	 * 
	 * @param config {@link XssConfiguration}
	 */
	private XssFilter(XssConfiguration config) {
		this.config = config;
	}

	/**
	 * 이 메소드는 XssFilter 객체를 리턴한다.
	 * 
	 * @return XssFilter 객체
	 */
	public static XssFilter getInstance() {
		return getInstance(CONFIG);
	}

	/**
	 * 이 메소드는 XssFilter 객체를 리턴한다.
	 * 
	 * @param fileName
	 *            XSS Filter 설정파일
	 * @return XssFilter 객체
	 */
	public static XssFilter getInstance(String fileName) {
		XssFilter filter = INSTANCE_MAP.get(fileName);

		if (filter != null) {
			return filter;
		}

		try {
			synchronized (XssFilter.class) {
				filter = INSTANCE_MAP.get(fileName);

				if (filter != null) {
					return filter;
				}

				filter = new XssFilter(XssConfiguration.newInstance(fileName));
				INSTANCE_MAP.put(fileName, filter);
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
				ioe.getMessage();
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
	 * @return attribute or ""
	 */
	public String doFilter(String tagName, String attName, String dirtyAttValue) {
		if (tagName == null || "".equals(tagName) || attName == null || "".equals(attName) || dirtyAttValue == null
			|| "".equals(dirtyAttValue)) {
			return "";
		}

		StringBuffer dirty = new StringBuffer();
		dirty.append('<').append(tagName);
		dirty.append(' ').append(attName).append('=').append(dirtyAttValue);
		dirty.append('>').append("</").append(tagName).append('>');

		Collection<Content> contents = MarkupParser.parse(dirty.toString());

		if (contents != null && !contents.isEmpty()) {
			for (Content content : contents) {
				if (content instanceof Element) {
					Element tag = Element.class.cast(content);
					this.checkRule(tag);

					Attribute att = tag.getAttribute(attName);

					if (att == null || att.isDisabled()) {
						return "";
					}

					return att.getValue();
				}
			}
		}

		return "";
	}

	/**
	 * serialize
	 * 
	 * @param writer writer
	 * @param contents contents
	 * @throws IOException IOException
	 */
	private void serialize(Writer writer, Collection<Content> contents) throws IOException {
		if (contents != null && !contents.isEmpty()) {
			for (Content content : contents) {
				if (content instanceof Comment || content instanceof Text) {
					content.serialize(writer);
				} else if (content instanceof Element) {
					this.serialize(writer, Element.class.cast(content));
				}
			}
		}
	}

	/**
	 * serialize
	 * 
	 * @param writer writer
	 * @param element element
	 * @throws IOException IOException
	 */
	private void serialize(Writer writer, Element element) throws IOException {
		if (!element.isDisabled()) {
			checkRule(element);
		}

		if (element.isDisabled()) {
			writer.write(BAD_TAG_INFO);
			writer.write("&lt;");
			writer.write(element.getName());
		} else if (element.existDisabledAttribute()) {
			writer.write(BAD_ATT_INFO);
			writer.write('<');
			writer.write(element.getName());
		} else {
			writer.write('<');
			writer.write(element.getName());
		}

		Collection<Attribute> atts = element.getAttributes();

		if (atts != null && !atts.isEmpty()) {
			for (Attribute att : atts) {
				if (!element.isDisabled() && att.isDisabled()) {
					continue;
				} else {
					writer.write(' ');
					att.serialize(writer);
				}
			}
		}

		writer.write((element.isDisabled()) ? "&gt;" : ">");

		if (!element.isEmpty()) {
			this.serialize(writer, element.getContents());
		}

		//Cross End Tag를 고려하여 닫힌 Tag라면 Element뒤에 EndTag가 존재하지 않기때문에 여기서 리턴한다.
		if (element.isXClosed()) {
			//System.out.println("isXClosed " + element.getName());
			return;
		}

		if (element.isClosed()) {
			if (element.isDisabled()) {
				writer.write("&lt;/");
				writer.write(element.getName());
				writer.write("&gt;");
			} else {
				writer.write("</");
				writer.write(element.getName());
				writer.write('>');
			}
		}
	}

	/**
	 * check rule
	 * 
	 * @param element element
	 */
	private void checkRule(Element element) {
		ElementRule tagRule = this.config.getElementRule(element.getName());

		if (tagRule == null) {
			element.setEnabled(false);
			return;
		}

		tagRule.checkEndTag(element);
		tagRule.checkDisabled(element);
		tagRule.disableNotAllowedAttributes(element);
		tagRule.disableNotAllowedChildElements(element);

		Collection<Attribute> atts = element.getAttributes();

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

		tagRule.excuteListener(element);
	}
}
