/*
 *	Copyright 2014 Naver Corp.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *		http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 */	
package com.nhncorp.lucy.security.xss;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.nhncorp.lucy.security.xss.config.AttributeRule;
import com.nhncorp.lucy.security.xss.config.ElementRule;
import com.nhncorp.lucy.security.xss.config.XssConfiguration;
import com.nhncorp.lucy.security.xss.markup.Attribute;
import com.nhncorp.lucy.security.xss.markup.Comment;
import com.nhncorp.lucy.security.xss.markup.Content;
import com.nhncorp.lucy.security.xss.markup.Description;
import com.nhncorp.lucy.security.xss.markup.Element;
import com.nhncorp.lucy.security.xss.markup.IEHackExtensionElement;
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
 * @author Naver Labs
 *
 */
public final class XssFilter implements LucyXssFilter {
	private static final Log LOG = LogFactory.getLog(XssFilter.class);

	private static final String BAD_TAG_INFO = "<!-- Not Allowed Tag Filtered -->";
	private static final String BAD_ATT_INFO_START = "<!-- Not Allowed Attribute Filtered (";
	private static final String BAD_ATT_INFO_END = ") -->";
	private static final String REMOVE_TAG_INFO_START = "<!-- Removed Tag Filtered (";
	private static final String REMOVE_TAG_INFO_END = ") -->";
//	private static final String ELELMENT_NELO_MSG = " (Disabled Element)";
//	private static final String ATTRIBUTE_NELO_MSG = " (Disabled Attribute)";
//	private static final String ELELMENT_REMOVE_NELO_MSG = " (Removed Element)";
	private static final String CONFIG = "lucy-xss-superset.xml";
	private static final String IE_HACK_EXTENSION = "IEHackExtension";
	private boolean withoutComment;
//	private boolean isNeloLogEnabled;
	private String service;
//	private String neloElementMSG;
//	private String neloAttrMSG;
//	private String neloElementRemoveMSG;
	private String blockingPrefix;
	private boolean blockingPrefixEnabled;
	private boolean filteringTagInCommentEnabled;

	private XssFilter commentFilter;
	private XssConfiguration config;

	private static final Map<FilterRepositoryKey, XssFilter> instanceMap = new HashMap<FilterRepositoryKey, XssFilter>();

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

	public static XssFilter getInstance(boolean withoutComment) throws XssFilterException {
		return getInstance(CONFIG, withoutComment);
	}

	public static XssFilter getInstance(String fileName) throws XssFilterException {
		return getInstance(fileName, false);
	}

	/**
	 * 이 메소드는 XssFilter 객체를 리턴한다.
	 *
	 * @param fileName
	 *            XSS Filter 설정파일
	 * @return XssFilter 객체
	 * @throws XssFilterException
	 *             설정파일 로딩 실패 시 발생(malformed인 경우).
	 */
	public static XssFilter getInstance(String fileName, boolean withoutComment) throws XssFilterException {
		/**
		XssFilter filter = instanceMap.get(fileName);
		if (filter != null) {
			filter.withoutComment = withoutComment;
			return filter;
		}
		 **/
		try {
			synchronized (XssFilter.class) {
				FilterRepositoryKey key = new FilterRepositoryKey(fileName, withoutComment);

				XssFilter filter = instanceMap.get(key);
				if (filter != null) {
					filter.withoutComment = withoutComment;
					return filter;
				}
				filter = new XssFilter(XssConfiguration.newInstance(fileName));
//				filter.isNeloLogEnabled = filter.config.enableNeloAsyncLog();
				filter.service = filter.config.getService();
				filter.blockingPrefixEnabled = filter.config.isEnableBlockingPrefix();
				filter.blockingPrefix = filter.config.getBlockingPrefix();

				filter.withoutComment = withoutComment;
/*				filter.neloElementMSG = ELELMENT_NELO_MSG;
				filter.neloAttrMSG = ATTRIBUTE_NELO_MSG;
				filter.neloElementRemoveMSG = ELELMENT_REMOVE_NELO_MSG;*/

				filter.filteringTagInCommentEnabled = filter.config.isFilteringTagInCommentEnabled();

				if (filter.filteringTagInCommentEnabled && ! filter.config.isNoTagAllowedInComment()) {

					filter.commentFilter = XssFilter.getCommentFilterInstance(filter.config);

				}

				instanceMap.put(key, filter);

				return filter;
			}
		} catch (Exception e) {
			throw new XssFilterException(e.getMessage());
		}
	}

	/**
	 * 이 메소드는 주석 내 태그 필터링을 위한 XssFilter 객체를 리턴한다.
	 *
	 * @param config
	 *            XSS Filter Configuration
	 * @return XssFilter 객체
	 */
	public static XssFilter getCommentFilterInstance(XssConfiguration config) {

		XssFilter filter = new XssFilter(config);
//		filter.isNeloLogEnabled = filter.config.enableNeloAsyncLog();
		filter.service = filter.config.getService();
		filter.blockingPrefixEnabled = filter.config.isEnableBlockingPrefix();
		filter.blockingPrefix = filter.config.getBlockingPrefix();

		filter.withoutComment = true;
/*		filter.neloElementMSG = ELELMENT_NELO_MSG;
		filter.neloAttrMSG = ATTRIBUTE_NELO_MSG;
		filter.neloElementRemoveMSG = ELELMENT_REMOVE_NELO_MSG;*/

		filter.filteringTagInCommentEnabled = true;

		return filter;
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
	 * 변환하거나, 삭제하는 기능을 제공한다. <br/> {@code "lucy-xss.xml"} 설정(사용자 설정 파일)에 따라 필터링을 수행한다.
	 * 사용자 설정 파일을 명시적으로 지정하지 않는 getInstance() 로 필터 객체를 생성했을 경우, lucy-xss-superset.xml 설정을 사용한다.
	 *
	 * @param dirty
	 *            XSS({@code Cross Site Scripting})이 포함된 위험한 코드.
	 * @return 신뢰할 수 있는 코드.
	 */
	public String doFilter(String dirty) {
		StringWriter writer = new StringWriter();
		doFilter(dirty, writer);
		return writer.toString();
	}

	/**
	 * 이 메소드는 XSS({@code Cross Site Scripting})이 포함된 위험한 코드에 대하여 신뢰할 수 있는 코드로
	 * 변환하거나, 삭제하는 기능을 제공한다. <br/> {@code "lucy-xss.xml"} 설정(사용자 설정 파일)에 따라 필터링을 수행한다.
	 * 사용자 설정 파일을 명시적으로 지정하지 않는 getInstance() 로 필터 객체를 생성했을 경우, lucy-xss-superset.xml 설정을 사용한다.
	 * 
	 * @param dirty
	 *            XSS({@code Cross Site Scripting})이 포함된 위험한 코드.
	 * @param writer            
	 * @return 신뢰할 수 있는 코드.
	 */
	public void doFilter(String dirty, Writer writer) {
		StringWriter neloLogWriter = new StringWriter();

		if (dirty == null || dirty.length() == 0) {
			LOG.debug("target string is empty. doFilter() method end.");
			return;
		}

		Collection<Content> contents = MarkupParser.parse(dirty);

		if (contents != null && !contents.isEmpty()) {
			try {
				this.serialize(writer, contents, neloLogWriter);
			} catch (IOException ioe) {
			}
		}

/*		if (this.isNeloLogEnabled) {
			String neloStr = neloLogWriter.toString();
			if (neloStr != null && neloStr.length() > 0) {
				LOG.error("@[" + this.service + "]" + neloStr);
			}
		}*/
	}

	/**
	 * 테스트 코드에서 neloLog 테스트를 위해 만든, 메소드. Access Modifier 가 default 여서 외부로 노출되지 않는다.
	 * @param dirty
	 * @param writer
	 * @param neloLogWriter
	 */
/*	String doFilterNelo(String dirty) {
		StringWriter neloLogWriter = new StringWriter();
		StringWriter writer = new StringWriter();
		if (dirty == null || "".equals(dirty)) {
			LOG.debug("target string is empty. doFilter() method end.");
			return null;
		}

		Collection<Content> contents = MarkupParser.parse(dirty);

		if (contents != null && !contents.isEmpty()) {
			try {
				this.serialize(writer, contents, neloLogWriter);
			} catch (IOException ioe) {
			}
		}

		String neloStr = neloLogWriter.toString();

		if (this.isNeloLogEnabled) {
			if (neloStr != null && neloStr.length() > 0) {
				return "@[" + this.service + "]" + neloStr;
			} else {
				return neloStr;
			}
		} else {
			return "";
		}
	}*/

	/**
	 * 이 메소드는 특정 Tag 내 특정 Attribute의 값에 삽입되는 XSS({@code Cross Site Scripting})이
	 * 포함된 위험한 코드를 신뢰할 수 있는 코드로 변환하거나, 삭제하는 기능을 제공한다. <br/>
	 * {@code "lucy-xss.xml"} 설정(사용자 설정 파일)에 따라 필터링을 수행한다.
	 * 사용자 설정 파일을 명시적으로 지정하지 않는 getInstance() 로 필터 객체를 생성했을 경우, lucy-xss-superset.xml 설정을 사용한다.
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
		if (tagName == null || tagName.length() == 0 || attName == null || attName.length() == 0 || dirtyAttValue == null || dirtyAttValue.length() == 0) {
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
					if (att != null) {
						if (att.isDisabled()) {
							return "";
						} else {
							return att.getValue();
						}
					}
				}
			}
		}

		return "";
	}

	private void serialize(Writer writer, Collection<Content> contents, StringWriter neloLogWriter) throws IOException {
		if (contents != null && !contents.isEmpty()) {
			for (Content content : contents) {
				if (content instanceof Text || content instanceof Description) {
					content.serialize(writer);
				} else if (content instanceof Comment) {
					this.serialize(writer, Comment.class.cast(content));
				} else if (content instanceof IEHackExtensionElement) {
					this.serialize(writer, IEHackExtensionElement.class.cast(content), neloLogWriter);
				} else if (content instanceof Element) {
					this.serialize(writer, Element.class.cast(content), neloLogWriter);
				}
			}
		}
	}

	private void serialize(Writer writer, Comment comment) throws IOException {

		comment.serializeFilteringTagInComment(writer, this.filteringTagInCommentEnabled, this.commentFilter);
	}

	private void serialize(Writer writer, IEHackExtensionElement ie, StringWriter neloLogWriter) throws IOException {

		ElementRule iEHExRule = this.config.getElementRule(IE_HACK_EXTENSION);

		if (iEHExRule != null) {
			iEHExRule.checkEndTag(ie);
			iEHExRule.checkDisabled(ie);
			iEHExRule.excuteListener(ie);
		} else {
			ie.setEnabled(false);
		}

		if (writer == null) {
			return;
		}

		if (ie.isDisabled()) { // IE Hack 태그가 비활성화 되어 있으면, 태그 삭제.
		/*	if (this.isNeloLogEnabled) {
				neloLogWriter.write(this.neloElementRemoveMSG);
				neloLogWriter.write(ie.getName() + "\n");
			}*/
			if (!this.withoutComment) {
				writer.write(REMOVE_TAG_INFO_START);
				writer.write(ie.getName().replaceAll("<", "&lt;").replaceFirst(">", "&gt;"));
				writer.write(REMOVE_TAG_INFO_END);
			}

			if (!ie.isEmpty()) {
				this.serialize(writer, ie.getContents(), neloLogWriter);
			}
		} else {
			// \s : A whitespace character, short for [ \t\n\x0b\r\f]
			// * : Occurs zero or more times, is short for {0,}
			ie.serialize(writer);

			if (!ie.isEmpty()) {
				this.serialize(writer, ie.getContents(), neloLogWriter);
			}

			if (ie.isClosed()) {
				// 중첩 IE Hack 태그 처리 로직(메일서비스개발랩 요구사항)
				// IE Hack 시작 태그의 종류 판별 및 태그맞춤 cf) 시작 스트링이 <!-- 인지 <! 인지에 따라 IE Hack 닫는 태그 달라짐.
				String stdName = ie.getName().replaceAll("-->", ">").replaceFirst("<!--\\s*", "<!--").replaceAll("]\\s*>", "]>");
				
				if(stdName.indexOf("<!--") != -1) {
					writer.write("<![endif]-->");
				} else {
					writer.write("<![endif]>");
				}
			}
		}
	}

	private void serialize(Writer writer, Element element, StringWriter neloLogWriter) throws IOException {
		boolean hasAttrXss = false;
		checkRuleRemove(element);

		if (element.isRemoved()) {
		/*	if (this.isNeloLogEnabled) {
				neloLogWriter.write(this.neloElementRemoveMSG);
				neloLogWriter.write(element.getName() + "\n");
			}*/

			if (!this.withoutComment) {
				writer.write(REMOVE_TAG_INFO_START);
				writer.write(element.getName());
				writer.write(REMOVE_TAG_INFO_END);
			}

			if (!element.isEmpty()) {
				this.serialize(writer, element.getContents(), neloLogWriter);
			}
		} else {
			//TODO 코드 리뷰 필요 
			// v1.3.3 & v1.5.1 BEFORE if (!element.isDisabled()) {
			if ((!element.isDisabled() || this.blockingPrefixEnabled)) {
				checkRule(element);
			}

			if (element.isDisabled()) {
				/*if (this.isNeloLogEnabled) {
					neloLogWriter.write(this.neloElementMSG);
					neloLogWriter.write(element.getName() + "\n");
				}*/

				if (this.blockingPrefixEnabled) { //BlockingPrefix를 사용하는 설정인 경우, <, > 에 대한 Escape 대신에 Element 이름을 조작하여 동작을 막는다.
					element.setName(this.blockingPrefix + element.getName());
					element.setEnabled(true); // 아래 close 태그 만드는 부분에서 escape 처리를 안하기 위한 꽁수. isBlockingPrefixEnabled 검사하도록 로직 수정.
					//writer.write('<');
					//writer.write(element.getName());
				} else { //BlockingPrefix를 사용하지 않는 설정인 경우, <, > 에 대한 Escape 처리.
					if (!this.withoutComment) {

						writer.write(BAD_TAG_INFO);
					}

					writer.write("&lt;");
					writer.write(element.getName());

				}
			}

			if (!element.isDisabled() && !this.withoutComment && element.existDisabledAttribute()) {
				writer.write(BAD_ATT_INFO_START);
			}

			Collection<Attribute> atts = element.getAttributes();

			StringWriter attrSw = new StringWriter();
			StringWriter attrXssSw = new StringWriter();

			if (atts != null && !atts.isEmpty()) {
				for (Attribute att : atts) {
					if (!element.isDisabled() && att.isDisabled()) {
						hasAttrXss = true;

						if (!this.withoutComment) {
							attrXssSw.write(' ');
							att.serialize(attrXssSw);
						}
					} else {
						attrSw.write(' ');
						att.serialize(attrSw);
					}
				}
			}

			if (hasAttrXss) {
				String attrXssString = attrXssSw.toString();
				/*if (this.isNeloLogEnabled) {
					neloLogWriter.write(this.neloAttrMSG);
					neloLogWriter.write(element.getName());
					neloLogWriter.write(attrXssString + "\n");
				}*/

				if (!this.withoutComment) {
					writer.write(attrXssString);
					writer.write(BAD_ATT_INFO_END);
				}
			}

			if (!element.isDisabled()) {
				writer.write('<');
				writer.write(element.getName());
			}

			writer.write(attrSw.toString());

			if (element.isStartClosed()) {

				writer.write(element.isDisabled() ? " /&gt;" : " />");

			} else {

				writer.write(element.isDisabled() ? "&gt;" : ">");
			}

			if (!element.isEmpty()) {
				this.serialize(writer, element.getContents(), neloLogWriter);
			}

			if (element.isClosed()) {
				if (element.isDisabled() && !this.blockingPrefixEnabled) {
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
	}

	private void checkRuleRemove(Element element) {
		ElementRule tagRule = this.config.getElementRule(element.getName());
		if (tagRule == null) {
			element.setEnabled(false);
			return;
		}

		tagRule.checkRemoveTag(element);
		if (element.isRemoved()) {
			tagRule.excuteListener(element);
		}
	}

	private void checkRule(Element element) {

		ElementRule tagRule = this.config.getElementRule(element.getName());
		if (tagRule == null) {
			// v1.3.3 & v1.5.2 BEFORE
			//element.setEnabled(false);
			//return;
			//TODO 코드 리뷰 필요
			tagRule = new ElementRule(element.getName());
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
					if (!attRule.getExceptionTagList().contains(element.getName().toLowerCase())) {
						//Exception 리스트에 포함이 안되면, 
						//attribute Rule에 따라 disable 값을 설정한다.
						attRule.checkDisabled(att);
					} else {
						//Exception 리스트에 포함이 되면,
						//Rule과 반대로 disable 값을 설정한다.
						attRule.checkDisabled(att);
						att.setEnabled(att.isDisabled());
					}
					attRule.checkAttributeValue(att);
					attRule.executeListener(att);
				}
			}
		}

		tagRule.excuteListener(element);
	}
}
