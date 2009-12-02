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
 * @author Web Platform Development Team
 * @version $Rev: 22446 $, $Date: 2009-09-24 11:29:24 +0900 (목, 24 9 2009) $
 */
public final class MarkupParser {
	private static ParsingGrammar grammar = ParsingGrammar.getInstance();

	/**
	 * Instantiates a new markup parser.
	 */
	private MarkupParser() {
	}

	/**
	 * 이 메소드는 Markup이 포함된 {@code String} 데이터를 {@code Collection} 형태로 파싱을 수행한다.
	 * 
	 * @param input	Markup이 포함된 {@code String} 데이터.
	 * @return	{@code Collection}.
	 */
	public static Collection<Content> parse(String input) {
		if (input == null || "".equals(input)) {
			return null;
		}

		LinkedList<Content> result = new LinkedList<Content>();
		LinkedList<Element> stack = null;
		Token root = grammar.tokenize(input);

		if (root == null) {
			return result;
		}

		List<Token> tempList = null;

		if (root != null && root.getChildren() != null) {
			tempList = root.getChildren();
		}

		for (int i = 0; (tempList != null && i < tempList.size()); i++) {
			Token tk = tempList.get(i);

			//for (Token t : root.getChildren()) {
			String tokenName = tk.getName();

			if ("comment".equals(tokenName)) {
				String comment = tk.getText();

				if (comment != null && !"".equals(comment)) {
					comment = comment.substring(4, comment.length() - 3);
				}

				result.add(new Comment(comment));

			} else if ("startTag".equals(tokenName)) {

				Element element = getStartedTagElement(tk);

				if (stack == null) {
					stack = new LinkedList<Element>();
				}

				stack.addFirst(element);
				result.add(element);
			} else if ("endTag".equals(tokenName)) {
				boolean flag = false;

				String tagName = null;

				if (tk != null) {
					Token token = tk.getChild("tagName");

					if (token != null) {
						tagName = token.getText();
					}
				}

				boolean isXCloseTag = false;

				if (stack != null) {

					LinkedList<Element> tmp = new LinkedList<Element>();
					Element element = null;

					while (!stack.isEmpty() && (element = stack.removeFirst()) != null) {
						//tagName(EndTag)와 호응하는 OpenTag라면,
						if (tagName.equalsIgnoreCase(element.getName())) {
							if (!(element.isXOpenTag())) {
								closeElement(stack, result, tmp, element);
								flag = true;
							} else {
								closeXElement(stack, tmp, element);
								isXCloseTag = true;
								flag = false;
							}

							break; //while break

						} else {
							//tagName(EndTag)와 호응하지 않는 element(OpenTag)라면,
							element.setXOpenTag(true); // element는 isXOpenTag = true로 세팅한다.
							tmp.add(element); // tmpStack에 element를 임시로 저장한다.
						}

					} //while

					if (tmp != null && !tmp.isEmpty()) {
						//tmp.isEmpty = flase 라면, setClose() metohd내부 while 문이 stack.isEmpty() = true가 될 때까지 looping, 즉 stack은 지금 비어있는 상태이다.  
						stack = tmp;
					}

				} //if

				if (!flag) {
					if (tk != null) {
						result.add(new Text(tk.getText(), isXCloseTag));
					}
				}

			} else {
				//tk가 text인 경우 : 주석(comment)or tag 가 아닌 경우
				result.add(new Text(tk.getText()));
			}
		}

		return result;
	}

	/**
	 * 이 메소드는 Element(XElement와 다름)를 Close한다.
	 * XElement는 outerElement가 Close된 상태에서 닫히지 않았던 innerElement 이다.
	 * e.g. <p><font></p></font> : <font>는 XElement이다. <p>는 Element이다.
	 * @param stack LinkedList<Element> start tag를 저장하는 stack
	 * @param result LinkedList<Content> start tag, 주석, 텍스트를 저장하는 list
	 * @param tmp LinkedList<Element> 지금까지 저장된 start tag {@code stack}에서 start tag를 찾지 못했을 때, stack에서 remove 했던 start tags를 임시로 저장하는 tmp stack
	 * @param element Element
	 */
	private static void closeElement(LinkedList<Element> stack, LinkedList<Content> result, LinkedList<Element> tmp,
			Element element) {
		Content content = null;

		while (!result.isEmpty() && (content = result.getLast()) != null) {
			if (content == element) {
				element.setXClose(false);
				element.setClose(true);

				//outer tag를 닫기 전에 inner open tags 중에서 close 되지 않은 tag를 stack top에 저장한다.
				stack.addAll(0, tmp);
				tmp.clear();
				break;
			} else {
				if (stack.contains(content)) {
					stack.remove(content);
				}

				element.addContent(0, result.removeLast());
			}
		}
	}

	/**
	 * 이 메소드는 XElement를 Close한다.
	 * XElement는 outerElement가 Close된 상태에서 닫히지 않았던 innerElement 이다.
	 * e.g. <p><font></p></font> : <font>는 XElement이다. <p>는 Element이다.
	 * @param stack LinkedList<Element> start tag를 저장하는 stack
	 * @param tmp LinkedList<Element> 지금까지 저장된 start tag {@code stack}에서 start tag를 찾지 못했을 때, stack에서 remove 했던 start tags를 임시로 저장하는 tmp stack
	 * @param element Element
	 */
	private static void closeXElement(LinkedList<Element> stack, LinkedList<Element> tmp, Element element) {
		element.setXClose(true);
		element.setClose(true);
		stack.addAll(0, tmp);
		tmp.clear();
	}

	/**
	 * Gets the started tag element.
	 * 
	 * @param tk the t
	 * 
	 * @return the started tag element
	 */
	private static Element getStartedTagElement(Token tk) {
		String name = null;

		if (tk != null) {
			Token token = tk.getChild("tagName");

			if (token != null) {
				name = token.getText();
			}
		}

		Element element = new Element(name);

		//Element element = new Element(t.getChild("tagName").getText());

		List<Token> attTokens = null;

		if (tk != null) {
			attTokens = tk.getChildren("attribute");
		}

		if (attTokens != null) {
			for (Token attToken : attTokens) {
				Token attName = attToken.getChild("attName");
				Token attValue = attToken.getChild("attValue");

				if (attValue == null && attName != null) {
					element.putAttribute(new Attribute(attName.getText()));
				} else {
					if (attName != null) {
						element.putAttribute(new Attribute(attName.getText(), attValue.getText()));
					}
				}
			}
		}

		return element;
	}

	/**
	 * 이 메소드는 Markup이 포함된 {@code InputStream} 데이터를 {@code Collection} 형태로 파싱을 수행한다.
	 * 
	 * @param stream	Markup이 포함된 {@code InputStream}.
	 * @param cs	{@code InputStream}의 {@code Charset}.
	 * @return	{@code Collection}.
	 * @throws IOException	{@code InputStream}에 대한 I/O error 발생 시.
	 */
	public static Collection<Content> parse(InputStream stream, Charset cs) throws IOException {
		return parse(read(new InputStreamReader(stream, cs)));
	}

	/**
	 * Read.
	 * 
	 * @param reader the reader
	 * 
	 * @return the string
	 * 
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	private static String read(Reader reader) throws IOException {
		StringBuffer buffer = new StringBuffer();
		try {
			char[] cbuf = new char[1024];
			int rc = 0;

			while ((rc = reader.read(cbuf)) > 0) {
				buffer.append(cbuf, 0, rc);
			}
		} finally {
			reader.close();
		}

		return buffer.toString();
	}

	/**
	 * 이 메소드는 {@code Collection}의 내용을 String으로 보여준다.
	 * 
	 * @param contents	{@code Collection}.
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
				e.getMessage();
			}
		}

		return writer.toString();
	}
}
