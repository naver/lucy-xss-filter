package com.nhncorp.lucy.security.xss.markup;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;

/**
 * 이 클래스는 Tag 내에 있는 Attribute 을 나타내며, Attribute 이름과 그 값을 유지한다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22364 $, $Date: 2009-09-03 12:07:27 +0900 (목, 03 9 2009) $
 */
public class Attribute {

	/**
	 * Attribute 이름에 해당하는 멤버 변수이다.
	 */
	protected String name;

	/**
	 * Attribute 값에 해당하는 멤버 변수이다.
	 */
	protected String value;

	/**
	 * {@link com.nhncorp.lucy.security.xss.XssFilter XssFilter}에서 사용하는 멤버 변수로 
	 * Attribute 의 활성화 여부를 나타낸다.
	 * 
	 * 기본값은 {@code true}.
	 */
	protected boolean enabled = true;

	/**
	 * Name 으로 초기화하는 생성자.
	 * 
	 * @param name	Attribute name.
	 */
	public Attribute(String name) {
		this.name = name;
	}

	/**
	 * Name 과 Value 로 초기화하는 생성자.
	 * 
	 * @param name	Attribute name.
	 * @param value	Attribute value.
	 */
	public Attribute(String name, String value) {
		this.name = name;
		this.value = value;
	}

	/**
	 * 이 메소드는 Attribute name 을 반환한다. 만약 Name 이 널이면, ""을 반환한다.
	 * @return	Attribute name.
	 */
	public String getName() {
		return (this.name == null) ? "" : this.name;
	}

	/**
	 * 이 메소드는 Attribute value 을 반환한다. 만약 value 가 널이면, ""을 반환한다.<br/> 
	 * 값은 인용부호를 포함한다. 그 이유는 인용부호가 없이 값이 세팅 될 수도 있기 때문이다. 
	 * 
	 * @return	Attribute value.
	 */
	public String getValue() {
		return (this.value == null) ? "" : this.value;
	}

	/**
	 * 이 메소드는 Attribute 의 값을 세팅한다.
	 * 자동으로 인용부호를 할당 하지 않으므로 인용부호를 사용할 경우 value 에 포함시켜야 한다.
	 * 
	 * @param value	Attribute value.
	 */
	public void setValue(String value) {
		this.value = value;
	}

	/**
	 * 이 메소드는 Attribute 의 값이 존재하는지 그렇지 않은지 여부를 반환한다.
	 * 만약 값이 존재하지 않으면 {@code true}, 존재하면 {@code false} 을 반환한다.
	 * 
	 * @return	값이 존재하지 않으면 {@code true}, 존재하면 {@code false}.
	 */
	public boolean isMinimized() {
		return (this.value == null) ? true : false;
	}

	/**
	 * 이 메소드는 Attribute 의 {@code String} 형태로 표현한다.
	 * 포멧은 (Name=Value) 또는 (Name) 형태로 리턴된다.  
	 * @return String
	 */
	@Override
	public String toString() {
		StringWriter writer = new StringWriter();
		try {
			this.serialize(writer);
		} catch (IOException ioe) {
			ioe.getMessage();
		}

		return writer.toString();
	}

	/**
	 * 이 메소드는 Attribute 를 직렬화한다.
	 * 포멧은 (Name=Value) 또는 (Name) 형태로 수행된다.
	 * 또한 Value 값에 '<'과 '>'이 포함되어 있을 경우, 각각 {@code '&lt;', '&gt;'} 으로 변환한다.  
	 * 
	 * @param writer	Writer 객체.
	 * @throws IOException	I/O 에러 발생 시.
	 */
	public void serialize(Writer writer) throws IOException {
		if (writer == null) {
			return;
		}

		writer.write(this.getName());

		if (!this.isMinimized()) {
			writer.write('=');
			String value = this.getValue();
			int pos = 0;
			int length = value.length();
			boolean isOpenQuote = hasQuote(value, 0);
			boolean isCloseQuote = hasQuote(value, length - 1);

			if (!isOpenQuote) {
				//OpenQuote가 없으면 강제 삽입한다.
				if (!isCloseQuote) {
					//CloseQuote가 없으면 임으로 double quote \" 을 OpenQuote로 삽 입한다. 
					writer.write('\"');
				} else {
					//CloseQuote가 있으면 같은 종류의 OpenQuote를 삽입한다.
					char close = value.charAt(length - 1);
					writer.write(close);
				}
			}

			for (int i = 0; i < length; i++) {

				switch (value.charAt(i)) {
					case '<':
						if (i > pos) {
							writer.write(value, pos, i - pos);
						}

						writer.write("&lt;");
						pos = i + 1;
						break;
					case '>':
						if (i > pos) {
							writer.write(value, pos, i - pos);
						}

						writer.write("&gt;");
						pos = i + 1;
						break;
					default:
				}
			}

			if (length > pos) {
				writer.write(value, pos, length - pos);
			}

			if (!isOpenQuote && !isCloseQuote) {
				//앞서 OpenQuote가 없었고, CloseQuote도 없으면, \" close double quote를 강제 삽입
				writer.write('\"');
			}
		}
	}

	/**
	 * 사용자가 입력한 attribtue value가 quote를 포함하는지 검사
	 * @param attValue 사용자가 입력한 HTML Tag의 attribute value
	 * @param index open quote ( index = 0)와 close quote( index = length - 1) 여부를 확인하는 위치 
	 * @return hasQuote boolean
	 */
	private boolean hasQuote(String attValue, int index) {

		boolean hasQuote = false;

		switch (attValue.charAt(index)) {
			case '\"':
			case '\'':
			case '`':
				hasQuote = true;
				break;
			default:
		}

		return hasQuote;
	}

	/**
	 * 이 메소드는 Attribute 이 비활성 되어 있는지 여부를 리턴한다.
	 * {@link com.nhncorp.lucy.security.xss.XssFilter XssCleaner}에서 사용.
	 * 
	 * @return	Attribute 의 비활성 여부.
	 */
	public boolean isDisabled() {
		return !this.enabled;
	}

	/**
	 * 이 메소드는 Attribute 를 활성 또는 비활성 시킨다.
	 * 
	 * @param flag	{@code true}이면 활성, {@code false}이면 비활성.
	 */
	public void setEnabled(boolean flag) {
		this.enabled = flag;
	}
}
