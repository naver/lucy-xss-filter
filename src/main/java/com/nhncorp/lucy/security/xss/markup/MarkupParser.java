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
package com.nhncorp.lucy.security.xss.markup;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import com.nhncorp.lucy.security.xss.CommonUtils;
import com.nhncorp.lucy.security.xss.markup.rule.CharArraySegment;
import com.nhncorp.lucy.security.xss.markup.rule.ParsingGrammar;
import com.nhncorp.lucy.security.xss.markup.rule.Token;

/**
 * 이 클래스는 Markup이 포함된 Data({@code String or InputStream})을 {@link com.nhncorp.lucy.security.xss.markup.Content Content}의
 * {@code Collection} 형태로 파싱하는 기능을 제공한다.
 * <br/><br/>
 * Static 클래스로 구현이 되었으며, 사용법은 다음과 같다.
 * <pre>
 * ...
 * 	Collection&lt;Content&gt; contents = MarkupParser.parse(input);
 * ...
 * </pre>
 *
 * 파싱 과정은 파싱 룰을 통해 수행이 되며, 파싱 룰은 다음과 같다.
 * <pre>
 * 	contents	::= (comment | startTag | endTag | text)+
 *	comment		::= '&lt;!--' ([#x9-#xFFFD]* - '--&gt;') '--&gt;'
 *	startTag	::= '&lt;' tagName ([#x20#x9#xD#xA]+ attribute)* ([/#x20#x9#xD#xA]* '&gt;')?
 *	endTag		::= '&lt;/' [#x20#x9#xD#xA]* tagName [#x20#x9#xD#xA]* '&gt;'
 *	tagName		::= [^?!'"/&lt;&gt;#x20#x9#xD#xA]+
 *	attribute	::= attName ([#x20#x9#xD#xA]* '=' [#x20#x9#xD#xA]* attValue)?
 *	attName		::= [^=&lt;&gt;#x20#x9#xD#xA]+
 *	attValue	::= ('"' [^"&lt;]*  '"') | ("'" [^'&lt;]* "'")
 *					| [^&lt;&gt;#x20#x9#xD#xA]*
 *	text		::= [^&lt;]* | ('&lt;' [^&lt;]*)
 *
 *	위의 파싱 룰정의는 XML specification 에서 정의한 EBNF Notation 을 사용하였다.
 * </pre>
 *
 * @author Naver Labs
 *
 */
public final class MarkupParser {
	private static ParsingGrammar grammar = ParsingGrammar.getInstance();

	private MarkupParser() {
	}

	/**
	 * 이 메소드는 Markup이 포함된 {@code String} 데이터를 {@code Collection<Content>} 형태로 파싱을 수행한다.
	 *
	 * @param input	Markup이 포함된 {@code String} 데이터.
	 * @return	{@code Collection<Content>}.
	 */
	public static Collection<Content> parse(String input) {

		if (input == null || input.length() == 0) {
			return null;
		}

		LinkedList<Content> result = new LinkedList<Content>();

		LinkedList<Element> stack = null;
		//		Token root = grammar.tokenize(input);
		//		List<Token> children = root.getChildren();
		//		for (Token t : children) {
		CharArraySegment charArraySegment = new CharArraySegment(input);
		Token token;
		while ((token = grammar.nextToken(charArraySegment)) != null) {
			String tokenName = token.getName();
			if ("description".equals(tokenName)) {

				String description = token.getText();
				result.add(new Description(description));

			} else if ("comment".equals(tokenName)) {
				String comment = token.getText();
				if (comment != null && comment.length() != 0) {
					comment = comment.substring(4, comment.length() - 3);
				}
				result.add(new Comment(comment));

			} else if ("iEHExStartTag".endsWith(tokenName)) {

				Element element = new IEHackExtensionElement(token.getText());

				if (stack == null) {
					stack = new LinkedList<Element>();
				}

				stack.addFirst(element);
				result.add(element);

			} else if ("startTag".equals(tokenName)) {
				Token tagNameToken = token.getChild("tagName");
				if (tagNameToken == null) {
					continue;
				}

				Element element = new Element(tagNameToken.getText());
				List<Token> attTokens = token.getChildren("attribute");
				if (attTokens != null) {
					for (Token attToken : attTokens) {
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

				Token closeStartEnd = token.getChild("closeStartEnd");

				if (closeStartEnd == null) {

					if (stack == null) {
						stack = new LinkedList<Element>();
					}

					stack.addFirst(element);

				} else {
					element.setStartClose(true);

				}

				result.add(element);

			} else if ("iEHExEndTag".endsWith(tokenName)) {

				boolean flag = false;
				if (stack != null) {
					LinkedList<Element> tmp = new LinkedList<Element>();
					Element element;
					while (!stack.isEmpty() && (element = stack.removeFirst()) != null) {
						if (element instanceof IEHackExtensionElement) {
							Content content;
							while (!result.isEmpty() && (content = result.getLast()) != null) {
								if (content instanceof Element && content == element) {
									element.setClose(true);
									tmp.clear();
									break;
								} else {
									if (stack.contains(content)) {
										stack.remove(content);
									}

									element.addContent(0, result.removeLast());
								}
							}
							flag = true;
							break;
						} else {
							tmp.add(element);
						}
					}

					if (tmp != null && !tmp.isEmpty()) {
						stack = tmp;
					}
				}

				if (!flag) {
					result.add(new Text(token.getText()));
				}

			} else if ("endTag".equals(tokenName)) {
				Token tagNameToken = token.getChild("tagName");
				boolean flag = false;
				if (tagNameToken == null) {
					continue;
				}

				String tagName = tagNameToken.getText();

				if (stack != null) {
					LinkedList<Element> tmp = new LinkedList<Element>();
					Element element;
					while (!stack.isEmpty() && (element = stack.removeFirst()) != null) {
						if (tagName.equalsIgnoreCase(element.getName())) {
							Content content;
							while (!result.isEmpty() && (content = result.getLast()) != null) {
								if (content instanceof Element && content == element) {
									element.setClose(true);
									tmp.clear();
									break;
								} else {
									if (stack.contains(content)) {
										stack.remove(content);
									}

									element.addContent(0, result.removeLast());
								}
							}
							flag = true;
							break;
						} else {
							tmp.add(element);
						}
					}

					if (tmp != null && !tmp.isEmpty()) {
						stack = tmp;
					}
				}

				if (!flag) {
					result.add(new Text(token.getText()));
				}
			} else {
				result.add(new Text(token.getText()));
			}
		}

		return result;
	}

	/**
	 * 이 메소드는 Markup이 포함된 {@code InputStream} 데이터를 {@code Collection<Content>} 형태로 파싱을 수행한다.
	 *
	 * @param stream	Markup이 포함된 {@code InputStream}.
	 * @param cs	{@code InputStream}의 {@code Charset}.
	 * @return	{@code Collection<Content>}.
	 * @throws IOException	{@code InputStream}에 대한 I/O error 발생 시.
	 */
	public static Collection<Content> parse(InputStream stream, Charset cs) throws IOException {
		return parse(read(new InputStreamReader(stream, cs)));
	}

	private static String read(Reader reader) throws IOException {
		StringBuffer buffer = new StringBuffer();
		try {
			char[] cbuf = new char[1024];
			int rc;
			while ((rc = reader.read(cbuf)) > 0) {
				buffer.append(cbuf, 0, rc);
			}
		} finally {
			reader.close();
		}

		return buffer.toString();
	}

	/**
	 * 이 메소드는 {@code Collection<Content>}의 내용을 String으로 보여준다.
	 *
	 * @param contents	{@code Collection<Content>}.
	 * @return	{@code String}.
	 */
	public static String toString(Collection<Content> contents) {
		if (contents == null) {
			return "";
		}

		StringWriter writer = new StringWriter();
		for (Content content : contents) {
			try {
				content.serialize(writer);
			} catch (IOException e) {
			}
		}

		return writer.toString();
	}
}
