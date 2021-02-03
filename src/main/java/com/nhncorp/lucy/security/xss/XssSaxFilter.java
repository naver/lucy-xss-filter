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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.nhncorp.lucy.security.xss.config.AttributeRule;
import com.nhncorp.lucy.security.xss.config.ElementRule;
import com.nhncorp.lucy.security.xss.config.XssConfiguration;
import com.nhncorp.lucy.security.xss.config.XssSaxConfiguration;
import com.nhncorp.lucy.security.xss.listener.SecurityUtils;
import com.nhncorp.lucy.security.xss.listener.WhiteUrlList;
import com.nhncorp.lucy.security.xss.markup.Attribute;
import com.nhncorp.lucy.security.xss.markup.Comment;
import com.nhncorp.lucy.security.xss.markup.Description;
import com.nhncorp.lucy.security.xss.markup.Element;
import com.nhncorp.lucy.security.xss.markup.IEHackExtensionElement;
import com.nhncorp.lucy.security.xss.markup.MarkupSaxParser;
import com.nhncorp.lucy.security.xss.markup.Text;
import com.nhncorp.lucy.security.xss.markup.rule.CharArraySegment;
import com.nhncorp.lucy.security.xss.markup.rule.Token;

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
public final class XssSaxFilter implements LucyXssFilter {
	private static final Log LOG = LogFactory.getLog(XssSaxFilter.class);

	private static final String BAD_TAG_INFO = "<!-- Not Allowed Tag Filtered -->";
	private static final String BAD_ATT_INFO_START = "<!-- Not Allowed Attribute Filtered (";
	private static final String BAD_ATT_INFO_END = ") -->";
	private static final String REMOVE_TAG_INFO_START = "<!-- Removed Tag Filtered (";
	private static final String REMOVE_TAG_INFO_END = ") -->";
	/*private static final String ELELMENT_NELO_MSG = " (Disabled Element)";
	private static final String ATTRIBUTE_NELO_MSG = " (Disabled Attribute)";
	private static final String ELELMENT_REMOVE_NELO_MSG = " (Removed Element)";*/
	private static final String CONFIG = "lucy-xss-superset-sax.xml";
	private static final String IE_HACK_EXTENSION = "IEHackExtension";
	private boolean withoutComment;
	//private boolean isNeloLogEnabled;
	private String service;
	/*private String neloElementMSG;
	private String neloAttrMSG;
	private String neloElementRemoveMSG;*/
	private String blockingPrefix;
	private boolean blockingPrefixEnabled;
	private boolean filteringTagInCommentEnabled;

	private XssSaxFilter commentFilter;
	private XssSaxConfiguration config;

	private static final Map<FilterRepositoryKey, XssSaxFilter> instanceMap = new HashMap<FilterRepositoryKey, XssSaxFilter>();

	private static final Pattern[] PARAMLIST = {Pattern.compile("['\"]?\\s*(?i:invokeURLs)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:autostart)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:allowScriptAccess)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:allowNetworking)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:autoplay)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:enablehref)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:enablejavascript)\\s*['\"]?"),
		Pattern.compile("['\"]?\\s*(?i:nojava)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:AllowHtmlPopupwindow)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:enableHtmlAccess)\\s*['\"]?")};

	private static final Pattern[] URLNAMES = {Pattern.compile("['\"]?\\s*(?i:url)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:href)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:src)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:movie)\\s*['\"]?")};

	private static boolean containsURLName(String name) {
		for (Pattern pattern : URLNAMES) {
			if (pattern.matcher(name).matches()) {
				return true;
			}
		}
		return false;
	}

	private boolean isWhiteUrl(String url) {
		WhiteUrlList list = WhiteUrlList.getInstance();
		if (list != null && list.contains(url)) {
			return true;
		}

		return false;
	}

	private XssSaxFilter(XssSaxConfiguration config) {
		this.config = config;
	}

	/**
	 * 이 메소드는 XssFilter 객체를 리턴한다.
	 *
	 * @return XssFilter 객체
	 * @throws XssFilterException
	 *             {@code "lucy-xss.xml"} 로딩 실패 시 발생(malformed인 경우).
	 */
	public static XssSaxFilter getInstance() throws XssFilterException {
		return getInstance(CONFIG, false);
	}

	public static XssSaxFilter getInstance(boolean withoutComment) throws XssFilterException {
		return getInstance(CONFIG, withoutComment);
	}

	public static XssSaxFilter getInstance(String fileName) throws XssFilterException {
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
	public static XssSaxFilter getInstance(String fileName, boolean withoutComment) throws XssFilterException {
		/**
		XssFilter filter = instanceMap.get(fileName);
		if (filter != null) {
			filter.withoutComment = withoutComment;
			return filter;
		}
		 **/
		try {
			synchronized (XssSaxFilter.class) {
				FilterRepositoryKey key = new FilterRepositoryKey(fileName, withoutComment);

				XssSaxFilter filter = instanceMap.get(key);
				if (filter != null) {
					return filter;
				}

				filter = new XssSaxFilter(XssSaxConfiguration.newInstance(fileName));
				filter.withoutComment = withoutComment;
//				filter.isNeloLogEnabled = filter.config.enableNeloAsyncLog();
				filter.service = filter.config.getService();
				filter.blockingPrefixEnabled = filter.config.isEnableBlockingPrefix();
				filter.blockingPrefix = filter.config.getBlockingPrefix();

			/*	filter.neloElementMSG = ELELMENT_NELO_MSG;
				filter.neloAttrMSG = ATTRIBUTE_NELO_MSG;
				filter.neloElementRemoveMSG = ELELMENT_REMOVE_NELO_MSG;*/

				filter.filteringTagInCommentEnabled = filter.config.isFilteringTagInCommentEnabled();

				if (filter.filteringTagInCommentEnabled && ! filter.config.isNoTagAllowedInComment()) {

					filter.commentFilter = XssSaxFilter.getCommentFilterInstance(filter.config);

				}

				instanceMap.put(key, filter);
				return filter;
			}
		} catch (Exception e) {
			throw new XssFilterException(e.getMessage());
		}
	}

	/**
	 * 이 메소드는 주석 내 태그 필터링을 위한 XssSaxFilter 객체를 리턴한다.
	 *
	 * @param config
	 *            XssSax Filter Configuration
	 * @return XssSaxFilter 객체
	 */
	public static XssSaxFilter getCommentFilterInstance(XssSaxConfiguration config) {

		XssSaxFilter filter = new XssSaxFilter(config);
//		filter.isNeloLogEnabled = filter.config.enableNeloAsyncLog();
		filter.service = filter.config.getService();
		filter.blockingPrefixEnabled = filter.config.isEnableBlockingPrefix();
		filter.blockingPrefix = filter.config.getBlockingPrefix();

		filter.withoutComment = true;
	/*	filter.neloElementMSG = ELELMENT_NELO_MSG;
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
	public XssSaxConfiguration getConfig() {
		return this.config;
	}

	/**
	 * 이 메소드는 XSS({@code Cross Site Scripting})이 포함된 위험한 코드에 대하여 신뢰할 수 있는 코드로
	 * 변환하거나, 삭제하는 기능을 제공한다. <br/> {@code "lucy-xss-sax.xml"} 설정(사용자 설정 파일)에 따라 필터링을 수행한다.
	 * 사용자 설정 파일을 명시적으로 지정하지 않는 getInstance() 로 필터 객체를 생성했을 경우, lucy-xss-superset-sax.xml 설정을 사용한다.
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
	 * 변환하거나, 삭제하는 기능을 제공한다. <br/> {@code "lucy-xss-sax.xml"} 설정(사용자 설정 파일)에 따라 필터링을 수행한다.
	 * 사용자 설정 파일을 명시적으로 지정하지 않는 getInstance() 로 필터 객체를 생성했을 경우, lucy-xss-superset-sax.xml 설정을 사용한다.
	 *
	 * @param dirty
	 *            XSS({@code Cross Site Scripting})이 포함된 위험한 코드.
	 * @param writer 필터링 결과를 write 할 writer 객체. 이 메소드가 종료되면 writer 객체에 신뢰할 수 있는 코드가 담겨진다.
	 */
	public void doFilter(String dirty, Writer writer) {
		StringWriter neloLogWriter = new StringWriter();

		if (dirty == null || dirty.length() == 0) {
			LOG.debug("target string is empty. doFilter() method end.");
			return;
		}

		try {
			this.parseAndFilter(dirty, writer, neloLogWriter);
		} catch (IOException ioe) {
			LOG.error(ioe.getMessage(), ioe);
		}

		/*if (this.isNeloLogEnabled) {
			String neloStr = neloLogWriter.toString();
			if (neloStr != null && neloStr.length() > 0) {
				LOG.error("@[" + this.service + "]" + neloStr);
			}
		}*/
	}

	/**
	 * 이 메소드는 XSS({@code Cross Site Scripting})이 포함된 위험한 코드에 대하여 신뢰할 수 있는 코드로
	 * 변환하거나, 삭제하는 기능을 제공한다. <br/> {@code "lucy-xss-sax.xml"} 설정(사용자 설정 파일)에 따라 필터링을 수행한다.
	 * 사용자 설정 파일을 명시적으로 지정하지 않는 getInstance() 로 필터 객체를 생성했을 경우, lucy-xss-superset-sax.xml 설정을 사용한다.
	 *
	 * @param dirty XSS({@code Cross Site Scripting})이 포함된 위험한 코드 char[].
	 * @param offset char[] dirty 의 필터링 대상 시작위치
	 * @param count char[]의 dirty 의 필터링 대상 문자개수
	 * @param writer 필터링 결과를 write 할 writer 객체. 이 메소드가 종료되면 writer 객체에 신뢰할 수 있는 코드가 담겨진다.
	 */
	public void doFilter(char[] dirty, int offset, int count, Writer writer) {
		StringWriter neloLogWriter = new StringWriter();

		if (dirty == null || dirty.length == 0 || count == 0) {
			LOG.debug("target string is empty. doFilter() method end.");
			return;
		}

		try {
			this.parseAndFilter(dirty, offset, count, writer, neloLogWriter);
		} catch (IOException ioe) {
			LOG.error(ioe.getMessage(), ioe);
		}

		/*if (this.isNeloLogEnabled) {
			String neloStr = neloLogWriter.toString();
			if (neloStr != null && neloStr.length() > 0) {
				LOG.error("@[" + this.service + "]" + neloStr);
			}
		}*/
	}

	/**
	 * @param writer
	 * @param neloLogWriter
	 * @throws IOException
	 */
	private void parseAndFilter(String dirty, Writer writer, StringWriter neloLogWriter) throws IOException {
		if (dirty != null && dirty.length() > 0) {
			LinkedList<Element> stackForObjectTag = new LinkedList<Element>();
			LinkedList<String> stackForAllowNetworkingValue = new LinkedList<String>();

			CharArraySegment charArraySegment = new CharArraySegment(dirty);
			doParseAndFilter(writer, neloLogWriter, stackForObjectTag, stackForAllowNetworkingValue, charArraySegment);
		}
	}

	/**
	 * @param dirty
	 * @param offset
	 * @param writer
	 * @param count
	 * @param neloLogWriter
	 */
	private void parseAndFilter(char[] dirty, int offset, int count, Writer writer, StringWriter neloLogWriter) throws IOException{
		if (dirty != null && dirty.length > 0 && count >0) {
			LinkedList<Element> stackForObjectTag = new LinkedList<Element>();
			LinkedList<String> stackForAllowNetworkingValue = new LinkedList<String>();

			CharArraySegment charArraySegment = new CharArraySegment(dirty, offset, count);
			doParseAndFilter(writer, neloLogWriter, stackForObjectTag, stackForAllowNetworkingValue, charArraySegment);
		}
	}

	/**
	 * @param writer
	 * @param neloLogWriter
	 * @param stackForObjectTag
	 * @param stackForAllowNetworkingValue
	 * @param charArraySegment
	 * @throws IOException
	 */
	private void doParseAndFilter(Writer writer, StringWriter neloLogWriter, LinkedList<Element> stackForObjectTag, LinkedList<String> stackForAllowNetworkingValue, CharArraySegment charArraySegment) throws IOException {
		Token token;
		while ((token = MarkupSaxParser.parse(charArraySegment)) != null) {
			String tokenName = token.getName();

			if ("description".equals(tokenName)) {

				String description = token.getText();
				Description content = new Description(description);
				content.serialize(writer);

			} else if ("comment".equals(tokenName)) {
				String comment = token.getText();
				if (comment != null && comment.length() != 0) {
					comment = comment.substring(4, comment.length() - 3);
				}

				Comment content = new Comment(comment);
				content.serializeFilteringTagInComment(writer, this.filteringTagInCommentEnabled, this.commentFilter);

				//content.serialize(writer);

			} else if ("iEHExStartTag".endsWith(tokenName)) {
				IEHackExtensionElement iehackElement = new IEHackExtensionElement(token.getText());
				checkIEHackRule(iehackElement);

				if (iehackElement.isDisabled()) { // IE Hack 태그가 비활성화 되어 있으면, 태그 삭제.
				/*	if (this.isNeloLogEnabled) {
						neloLogWriter.write(this.neloElementRemoveMSG);
						neloLogWriter.write(iehackElement.getName() + "\n");
					}*/
					if (!this.withoutComment) {
						writer.write(REMOVE_TAG_INFO_START);
						writer.write(iehackElement.getName().replaceAll("<", "&lt;").replaceFirst(">", "&gt;"));
						writer.write(REMOVE_TAG_INFO_END);
					}
				}

				iehackElement.serialize(writer);

			} else if ("startTag".equals(tokenName)) {
				Token tagNameToken = token.getChild("tagName");
				if (tagNameToken == null) {
					continue;
				}

				String tagName = tagNameToken.getText();
				Element element = new Element(tagName);
				List<Token> attTokens = token.getChildren("attribute");
				if (attTokens != null) {
					for (Token attToken : attTokens) {
						if (attToken != null) {
							Token attName = attToken.getChild("attName");
							Token attValue = attToken.getChild("attValue");
							if (attName != null && attValue == null) {
								element.putAttribute(new Attribute(attName.getText()));
							} else if (attName != null && attValue != null) {
								String text = attValue.getText();
								text = CommonUtils.getQuotePair(text);
								element.putAttribute(new Attribute(attName.getText(), text));
							}
						}
					}
				}

				Token closeStartEnd = token.getChild("closeStartEnd");

				if (closeStartEnd != null) {
					element.setStartClose(true);

				}

				doObjectParamStartTagProcess(stackForObjectTag, stackForAllowNetworkingValue, element);

				this.serialize(writer, element, neloLogWriter);

			} else if ("iEHExEndTag".endsWith(tokenName)) {
				IEHackExtensionElement ie = new IEHackExtensionElement(token.getText());
				checkIEHackRule(ie);

				if (!ie.isDisabled()) { // IE Hack 태그가 비활성화 되어 있으면, end 태그 삭제.
					// 중첩 IE Hack 태그 처리 로직(메일서비스개발랩 요구사항)
					String stdName = ie.getName();
					if (stdName != null) {
						stdName = stdName.replaceFirst("<!--", "<!");
					}
					writer.write(stdName); // <!--[endif]--> 일 경우 IE에서 핵이 그데로 노출되는 문제 방지하기 위해 변환.
				}
			} else if ("endTag".equals(tokenName)) {
				Token tagNameToken = token.getChild("tagName");

				if (tagNameToken == null) {
					continue;
				}

				String tagName = tagNameToken.getText();

				boolean isObjectDisabled = false;
				if ("object".equalsIgnoreCase(tagName) && stackForObjectTag.size() > 0) {
					isObjectDisabled = doObjectEndTagProcess(writer, neloLogWriter, stackForObjectTag, stackForAllowNetworkingValue);

				}

				Element element = new Element(tagName);

				checkRuleRemove(element);

				if (!element.isRemoved()) {
					if (isObjectDisabled) {
						element.setEnabled(false);
					}

					//TODO 코드 리뷰 필요
					// v1.3.3 & v1.5.2 BEFORE if (!element.isDisabled()) {
					if (!element.isDisabled() || this.blockingPrefixEnabled) {
						checkRule(element);
					}

					if (element.isDisabled()) {
						if (this.blockingPrefixEnabled) { //BlockingPrefix를 사용하는 설정인 경우, <, > 에 대한 Escape 대신에 Element 이름을 조작하여 동작을 막는다.
							element.setName(this.blockingPrefix + element.getName());
							element.setEnabled(true);
							writer.write("</");
							writer.write(element.getName());
							writer.write('>');
						} else { //BlockingPrefix를 사용하지 않는 설정인 경우, <, > 에 대한 Escape 처리.
							writer.write("&lt;/");
							writer.write(element.getName());
							writer.write("&gt;");
						}
					} else {
						writer.write("</");
						writer.write(element.getName());
						writer.write('>');
					}
				}
			} else {
				Text content = new Text(token.getText());
				content.serialize(writer);
			}
		}
	}

	/**
	 * @param stackForObjectTag
	 * @param stackForAllowNetworkingValue
	 * @param element
	 */
	private void doObjectParamStartTagProcess(LinkedList<Element> stackForObjectTag, LinkedList<String> stackForAllowNetworkingValue, Element element) {

		if ("object".equalsIgnoreCase(element.getName())) {
			stackForObjectTag.push(element);
			boolean isDataWhiteUrl = false;

			Attribute dataUrl = element.getAttribute("data");

			if (dataUrl != null) { // data 속성이 존재하면 체크
				String dataUrlStr = dataUrl.getValue();
				isDataWhiteUrl = this.isWhiteUrl(dataUrlStr);

				// URL MIME 체크
				boolean isVulnerable = SecurityUtils.checkVulnerable(element, dataUrlStr, isDataWhiteUrl);

				if (isVulnerable) {
					element.setEnabled(false);
					return;
				}
			}

			if (isDataWhiteUrl) {
				stackForAllowNetworkingValue.push("\"all\""); // data속성의 url 값이 white url이면 allowNetworking 디폴트는 설정은 all
			} else {
				stackForAllowNetworkingValue.push("\"internal\""); // allowNetworking 디폴트는 설정은 internal
			}
		} else if (stackForObjectTag.size() > 0 && "param".equalsIgnoreCase(element.getName())) {
			Attribute nameAttr = element.getAttribute("name");
			Attribute valueAttr = element.getAttribute("value");

			if (nameAttr != null && valueAttr != null) {
				stackForObjectTag.push(element);
				if (containsURLName(nameAttr.getValue())) {
					stackForAllowNetworkingValue.pop();
					boolean whiteUrl = isWhiteUrl(valueAttr.getValue());

					if (whiteUrl) {
						stackForAllowNetworkingValue.push("\"all\""); // whiteUrl 일 경우 allowNetworking 설정은 all 로 변경
					} else {
						stackForAllowNetworkingValue.push("\"internal\""); // whiteUrl 이 아닐 경우 allowNetworking 설정은 internal 로 변경
					}
				}
			}
		}
	}

	/**
	 * @param writer
	 * @param neloLogWriter
	 * @param stackForObjectTag
	 * @param stackForAllowNetworkingValue
	 * @throws IOException
	 */
	private boolean doObjectEndTagProcess(Writer writer, StringWriter neloLogWriter, LinkedList<Element> stackForObjectTag, LinkedList<String> stackForAllowNetworkingValue) throws IOException {
		List<String> paramNameList = new ArrayList<String>();

		Element item = null;

		while (stackForObjectTag.size() > 0) {
			item = stackForObjectTag.pop();
			if ("object".equalsIgnoreCase(item.getName())) {
				break;
			} else {
				Attribute nameAttr = item.getAttribute("name");
				if (nameAttr != null) {
					paramNameList.add(nameAttr.getValue());
				}
			}

		}

		if (item == null || !"object".equalsIgnoreCase(item.getName())) {
			return false;
		} else if (item != null && item.isDisabled()) {
			return true;
		}

		// PARAMLIST (보안 파라미터(param) 설정)에 없는 param(paramNameList)을 확인해서 object 태그를 닫기 전에 추가해준다.
		for (int index = 0; index < PARAMLIST.length; index++) {
			Pattern pattern = PARAMLIST[index];

			boolean exist = false;
			for (String paramName : paramNameList) {
				if (pattern.matcher(paramName).matches()) {
					exist = true;
					break;
				}
			}

			if (!exist) {
				// 해당 패턴의 param 추가
				switch (index) {
					// <param name="invokeURLs" value="false" />
					case 0:
						Element invokeURLs = new Element("param");
						invokeURLs.putAttribute("name", "\"invokeURLs\"");
						invokeURLs.putAttribute("value", "\"false\"");
						this.serialize(writer, invokeURLs, neloLogWriter);
						break;

						// <param name="autostart" value="false" />
					case 1:
						Element autostart = new Element("param");
						autostart.putAttribute("name", "\"autostart\"");
						autostart.putAttribute("value", "\"false\"");
						this.serialize(writer, autostart, neloLogWriter);
						break;

						// <param name="allowScriptAccess" value="never" />
					case 2:
						Element allowScriptAccess = new Element("param");
						allowScriptAccess.putAttribute("name", "\"allowScriptAccess\"");
						allowScriptAccess.putAttribute("value", "\"never\"");
						this.serialize(writer, allowScriptAccess, neloLogWriter);
						break;

						// <param name="allowNetworking" value="all|internal" />

					case 3:
						Element allowNetworking = new Element("param");
						allowNetworking.putAttribute("name", "\"allowNetworking\"");
						allowNetworking.putAttribute("value", stackForAllowNetworkingValue.size() == 0 ? "\"internal\"" : stackForAllowNetworkingValue.pop());
						this.serialize(writer, allowNetworking, neloLogWriter);
						break;

						// <param name="autoplay" value="false" />
					case 4:
						Element autoplay = new Element("param");
						autoplay.putAttribute("name", "\"autoplay\"");
						autoplay.putAttribute("value", "\"false\"");
						this.serialize(writer, autoplay, neloLogWriter);
						break;

						// <param name="enablehref" value="flase" />
					case 5:
						Element enablehref = new Element("param");
						enablehref.putAttribute("name", "\"enablehref\"");
						enablehref.putAttribute("value", "\"false\"");
						this.serialize(writer, enablehref, neloLogWriter);
						break;

						// <param name="enablejavascript" value="flase" />
					case 6:
						Element enablejavascript = new Element("param");
						enablejavascript.putAttribute("name", "\"enablejavascript\"");
						enablejavascript.putAttribute("value", "\"false\"");
						this.serialize(writer, enablejavascript, neloLogWriter);
						break;

						// <param name="nojava" value="true" />
					case 7:
						Element nojava = new Element("param");
						nojava.putAttribute("name", "\"nojava\"");
						nojava.putAttribute("value", "\"true\"");
						this.serialize(writer, nojava, neloLogWriter);
						break;

						// <param name="AllowHtmlPopupwindow" value="false" />
					case 8:
						Element allowHtmlPopupwindow = new Element("param");
						allowHtmlPopupwindow.putAttribute("name", "\"AllowHtmlPopupwindow\"");
						allowHtmlPopupwindow.putAttribute("value", "\"false\"");
						this.serialize(writer, allowHtmlPopupwindow, neloLogWriter);
						break;

						// <param name="enableHtmlAccess" value="false" />
					case 9:
						Element enableHtmlAccess = new Element("param");
						enableHtmlAccess.putAttribute("name", "\"enableHtmlAccess\"");
						enableHtmlAccess.putAttribute("value", "\"false\"");
						this.serialize(writer, enableHtmlAccess, neloLogWriter);
						break;
					default:
						System.out.println("발생 할 수 없는 로직입니다.");
				}
			}
		}

		return false;
	}

	private void serialize(Writer writer, IEHackExtensionElement ie, StringWriter neloLogWriter) throws IOException {
		checkIEHackRule(ie);

		if (ie.isDisabled()) { // IE Hack 태그가 비활성화 되어 있으면, 태그 삭제.
			/*if (this.isNeloLogEnabled) {
				neloLogWriter.write(this.neloElementRemoveMSG);
				neloLogWriter.write(ie.getName() + "\n");
			}*/
			if (!this.withoutComment) {
				writer.write(REMOVE_TAG_INFO_START);
				writer.write(ie.getName().replaceAll("<", "&lt;").replaceFirst(">", "&gt;"));
				writer.write(REMOVE_TAG_INFO_END);
			}
		} else {
			// \s : A whitespace character, short for [ \t\n\x0b\r\f]
			// * : Occurs zero or more times, is short for {0,}
			String stdName = ie.getName().replaceAll("-->", ">").replaceFirst("<!--\\s*", "<!--").replaceAll("]\\s*>", "]>"); // IE에서 핵이 그데로 노출되는 문제 방지 및 공백제거처리

			int startIndex = stdName.indexOf("<!") + 1;
			int lastIntndex = stdName.lastIndexOf(">");

			String firststdName = stdName.substring(0, startIndex);
			String middlestdName = StringUtils.replaceEach(stdName.substring(startIndex, lastIntndex), new String[] {"<", ">"}, new String[] {"&lt;", "&gt;"});
			String laststdName = stdName.substring(lastIntndex);

			stdName = firststdName + middlestdName + laststdName;

			writer.write(stdName);

			//			if (ie.isClosed()) {
			//				writer.write("<![endif]-->");
			//			}
		}
	}

	/**
	 * @param ie
	 */
	private void checkIEHackRule(IEHackExtensionElement ie) {
		ElementRule iEHExRule = this.config.getElementRule(IE_HACK_EXTENSION);

		if (iEHExRule != null) {
			//iEHExRule.checkEndTag(ie);
			iEHExRule.checkDisabled(ie);
			iEHExRule.excuteListener(ie);
		} else {
			ie.setEnabled(false);
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
		} else {
			//TODO 코드 리뷰 필요
			// v1.3.3 & v1.5.2 BEFORE if (!element.isDisabled()) {
			if (!element.isDisabled() || this.blockingPrefixEnabled) {
				checkRule(element);
			}

			if (element.isDisabled()) {
			/*	if (this.isNeloLogEnabled) {
					neloLogWriter.write(this.neloElementMSG);
					neloLogWriter.write(element.getName() + "\n");
				}*/

				if (this.blockingPrefixEnabled) { //BlockingPrefix를 사용하는 설정인 경우, <, > 에 대한 Escape 대신에 Element 이름을 조작하여 동작을 막는다.
					element.setName(this.blockingPrefix + element.getName());
					element.setEnabled(true); // 아래 close 태그 만드는 부분에서 escape 처리를 안하기 위한 꽁수. isBlockingPrefixEnabled 검사하도록 로직 수정.
					//					writer.write('<');
					//					writer.write(element.getName());
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

			//			if (e.isClosed()) {
			//				if (e.isDisabled() && !this.isBlockingPrefixEnabled) {
			//					writer.write("&lt;/");
			//					writer.write(e.getName());
			//					writer.write("&gt;");
			//				} else {
			//					writer.write("</");
			//					writer.write(e.getName());
			//					writer.write('>');
			//				}
			//			}
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

		//tagRule.checkEndTag(e);
		tagRule.checkDisabled(element);
		//tagRule.disableNotAllowedAttributes(e);
		//tagRule.disableNotAllowedChildElements(e);

		Collection<Attribute> atts = element.getAttributes();
		if (atts != null && !atts.isEmpty()) {
			for (Attribute att : atts) {
				if (att.isDisabled()) {
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
