import java.nio.file.Files;
import java.nio.file.Path;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;

class CheckVersion {
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[0]);
        String version = args[1];
        var parser = DocumentBuilderFactory.newInstance();
        parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        int count = 0;
        try (var files = Files.walk(root.resolve("server"), 2)) {
            for (Path pom : files.filter(p -> p.getFileName().toString().equals("pom.xml")).toList()) {
                Element project = parser.newDocumentBuilder().parse(pom.toFile()).getDocumentElement();
                for (var node = project.getFirstChild(); node != null; node = node.getNextSibling()) {
                    if (!(node instanceof Element element)) continue;
                    String actual = switch (element.getTagName()) {
                        case "version" -> element.getTextContent().trim();
                        case "parent" -> element.getElementsByTagName("version").item(0).getTextContent().trim();
                        default -> null;
                    };
                    if (actual != null) {
                        if (!version.equals(actual)) throw new IllegalStateException(pom + ": expected " + version + ", got " + actual);
                        count++;
                    }
                }
            }
        }
        if (count != 6) throw new IllegalStateException("Expected six Maven project/parent versions, got " + count);
    }
}
