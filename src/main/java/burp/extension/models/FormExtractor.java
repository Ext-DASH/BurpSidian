package burp.extension.models;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FormExtractor {
    public static List<String> extractForms(String html) {
        List<String> forms = new ArrayList<>();

        Pattern pattern = Pattern.compile("<form (.*?) </form>", Pattern.DOTALL);
        Matcher matcher = pattern.matcher(html);

        while (matcher.find()) {
            forms.add(matcher.group(1).trim());
        }

        return forms;
    }
}
