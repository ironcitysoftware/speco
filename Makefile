JFLAGS = -Xdiags:verbose

LIB = lib/guava-21.0.jar

all: src/speco/Hack.class

src/%.class: src/%.java
	javac $(JFLAGS) -cp $(LIB) $^

.PHONY: clean
clean:
	$(RM) src/speco/*.class

.PHONY: run
run: src/speco/Hack.class
	java -cp $(LIB):src/ speco.Hack
