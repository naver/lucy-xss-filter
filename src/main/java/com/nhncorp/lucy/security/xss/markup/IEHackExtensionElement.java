package com.nhncorp.lucy.security.xss.markup;

import java.io.IOException;
import java.io.Writer;

public class IEHackExtensionElement extends Element {
	public IEHackExtensionElement(String name) {
		super(name);
	}

	@Override
	public void setName(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void serialize(Writer writer) throws IOException {

		if (writer == null) {
			return;
		}

		String valid = this.getName().replaceAll("-->", ">");
		writer.write(valid);

		if (!this.isEmpty()) {
			for (Content c : this.contents) {
				c.serialize(writer);
			}
		}

		if (this.isClosed) {
			writer.write("<![endif]-->");
		}
	}

}
