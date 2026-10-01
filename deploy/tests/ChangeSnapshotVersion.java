import java.nio.file.Files;
import java.nio.file.Path;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Element;

class ChangeSnapshotVersion {
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[0]).toRealPath();
        if (!root.toString().contains("/.tmp/")) throw new IllegalArgumentException("Only validation snapshots may be changed");
        var parser = DocumentBuilderFactory.newInstance();
        parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        var transformer = TransformerFactory.newInstance();
        transformer.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        try (var files = Files.walk(root.resolve("server"), 2)) {
            for (Path path : files.filter(p -> p.getFileName().toString().equals("pom.xml")).toList()) {
                var document = parser.newDocumentBuilder().parse(path.toFile());
                var project = document.getDocumentElement();
                for (var node = project.getFirstChild(); node != null; node = node.getNextSibling()) {
                    if (node instanceof Element element && element.getTagName().equals("version")) element.setTextContent(args[1]);
                    if (node instanceof Element element && element.getTagName().equals("parent")) {
                        element.getElementsByTagName("version").item(0).setTextContent(args[1]);
                    }
                }
                transformer.newTransformer().transform(new DOMSource(document), new StreamResult(path.toFile()));
            }
        }
        System.out.println("Snapshot Maven version changed to " + args[1]);
    }
}
