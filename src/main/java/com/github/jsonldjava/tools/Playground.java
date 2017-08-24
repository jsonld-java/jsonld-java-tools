package com.github.jsonldjava.tools;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import joptsimple.ValueConversionException;
import joptsimple.ValueConverter;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.cache.BasicHttpCacheStorage;
import org.apache.http.impl.client.cache.CacheConfig;
import org.apache.http.impl.client.cache.CachingHttpClientBuilder;
import org.eclipse.rdf4j.model.Model;
import org.eclipse.rdf4j.rio.RDFFormat;
import org.eclipse.rdf4j.rio.RDFParserRegistry;
import org.eclipse.rdf4j.rio.Rio;

import com.github.jsonldjava.core.DocumentLoader;
import com.github.jsonldjava.core.JsonLdConsts;
import com.github.jsonldjava.core.JsonLdApi;
import com.github.jsonldjava.core.JsonLdOptions;
import com.github.jsonldjava.core.JsonLdProcessor;
import com.github.jsonldjava.core.RDFDataset;
import com.github.jsonldjava.utils.JarCacheStorage;
import com.github.jsonldjava.utils.JsonUtils;

/**
 * A command-line-interface used to load and process JSON-LD and RDF files.
 */
public class Playground {

    public static void main(String[] args) throws Exception {

        final Map<String, RDFFormat> formats = getOutputFormats();
        final Set<String> outputForms = new LinkedHashSet<String>(
                Arrays.asList("compacted", "expanded", "flattened"));

        final OptionParser parser = new OptionParser();

        final OptionSpec<Void> help = parser.accepts("help").forHelp();

        final OptionSpec<String> base = parser.accepts("base").withRequiredArg()
                .ofType(String.class).defaultsTo("").describedAs("base URI");

        final OptionSpec<File> inputFile = parser.accepts("inputFile").withRequiredArg()
                .ofType(File.class).required().describedAs("The input file");

        final OptionSpec<File> context = parser.accepts("context").withRequiredArg()
                .ofType(File.class).describedAs("The context");

        final OptionSpec<RDFFormat> outputFormat = parser.accepts("format").withOptionalArg()
                .ofType(String.class).withValuesConvertedBy(new ValueConverter<RDFFormat>() {
                    @Override
                    public RDFFormat convert(String arg0) {
                        // Normalise the name to provide alternatives
                        final String formatName = arg0.replaceAll("-", "").replaceAll("/", "")
                                .toLowerCase();
                        if (formats.containsKey(formatName)) {
                            return formats.get(formatName);
                        }
                        throw new ValueConversionException("Format was not known: " + arg0
                                + " (Valid values are: " + formats.keySet() + ")");
                    }

                    @Override
                    public String valuePattern() {
                        return null;
                    }

                    @Override
                    public Class<RDFFormat> valueType() {
                        return RDFFormat.class;
                    }
                }).defaultsTo(RDFFormat.NQUADS)
                .describedAs("The output file format to use. Defaults to nquads. Valid values are: "
                        + formats.keySet());

        final OptionSpec<String> processingOption = parser.accepts("process").withRequiredArg()
                .ofType(String.class).required()
                .withValuesConvertedBy(new ValueConverter<String>() {
                    @Override
                    public String convert(String value) {
                        if (getProcessingOptions().contains(value.toLowerCase())) {
                            return value.toLowerCase();
                        }
                        throw new ValueConversionException("Processing option was not known: "
                                + value + " (Valid values are: " + getProcessingOptions() + ")");
                    }

                    @Override
                    public Class<String> valueType() {
                        return String.class;
                    }

                    @Override
                    public String valuePattern() {
                        return null;
                    }
                }).describedAs("The processing to perform. Valid values are: "
                        + getProcessingOptions().toString());

        final OptionSpec<String> outputForm = parser.accepts("outputForm").withOptionalArg()
                .ofType(String.class).defaultsTo("expanded")
                .withValuesConvertedBy(new ValueConverter<String>() {
                    @Override
                    public String convert(String value) {
                        if (outputForms.contains(value.toLowerCase())) {
                            return value.toLowerCase();
                        }
                        throw new ValueConversionException("Output form was not known: " + value
                                + " (Valid values are: " + outputForms + ")");
                    }

                    @Override
                    public String valuePattern() {
                        return null;
                    }

                    @Override
                    public Class<String> valueType() {
                        return String.class;
                    }
                }).describedAs(
                        "The way to output the results from fromRDF. Defaults to expanded. Valid values are: "
                                + outputForms);

        final OptionSpec<String> usernameOption = parser.accepts("username").withOptionalArg()
                .ofType(String.class).describedAs("username for basic authentication credentials");

        final OptionSpec<String> passwordOption = parser.accepts("password").withOptionalArg()
                .ofType(String.class).describedAs("password for basic authentication credentials (defaults to value of 'PASSWORD' environment property, if set, or empty string otherwise)");

        final OptionSpec<String> authHostOption = parser.accepts("authHost").withOptionalArg()
                .ofType(String.class).defaultsTo("localhost")
                .describedAs("host authentication scope");

        final OptionSpec<Integer> authPortOption = parser.accepts("authPort").withOptionalArg()
                .ofType(Integer.class).defaultsTo(443)
                .describedAs("host port authentication scope");

        final OptionSpec<Void> authInsecureOption = parser.accepts("insecure","Similar to `curl -k` or `curl --insecure`: if unspecified, all SSL connections are secure by default; if specified, trust everything (do not use for production!)");

        OptionSet options = null;

        try {
            options = parser.parse(args);
        } catch (final OptionException e) {
            System.out.println(e.getMessage());
            parser.printHelpOn(System.out);
            throw e;
        }

        if (options.has(help)) {
            parser.printHelpOn(System.out);
            return;
        }

        final JsonLdOptions opts = new JsonLdOptions("");
        Object inobj = null;
        Object ctxobj = null;

        opts.setBase(options.valueOf(base));
        opts.outputForm = options.valueOf(outputForm);
        opts.format = options.has(outputFormat) ? options.valueOf(outputFormat).getDefaultMIMEType()
                : JsonLdConsts.APPLICATION_NQUADS;
        final RDFFormat sesameOutputFormat = options.valueOf(outputFormat);
        final RDFFormat sesameInputFormat = Rio
                .getParserFormatForFileName(options.valueOf(inputFile).getName())
                .orElse(RDFFormat.JSONLD);

        final String processingOptionValue = options.valueOf(processingOption);

        if (!options.valueOf(inputFile).exists()) {
            System.out.println(
                    "Error: input file \"" + options.valueOf(inputFile) + "\" doesn't exist");
            parser.printHelpOn(System.out);
            return;
        }
        // if base is currently null, set it
        if (opts.getBase() == null || opts.getBase().equals("")) {
            opts.setBase(options.valueOf(inputFile).toURI().toASCIIString());
        }

        if (options.hasArgument(usernameOption)) {
            final String username = options.valueOf(usernameOption);
            final String envPassword = System.getenv("PASSWORD");
            final String password = options.hasArgument(passwordOption)
                    ? options.valueOf(passwordOption)
                    : (null != envPassword) ? envPassword : "";
            final String authHost = options.valueOf(authHostOption);
            final Integer authPort = options.valueOf(authPortOption);

            final DocumentLoader documentLoader = new DocumentLoader();

            final CredentialsProvider credsProvider = new BasicCredentialsProvider();
            credsProvider.setCredentials(
                    new AuthScope(authHost, authPort),
                    new UsernamePasswordCredentials(username, password));

            final CacheConfig cacheConfig = CacheConfig.custom()
                    .setMaxCacheEntries(1000)
                    .setMaxObjectSize(1024 * 128).build();

            if (options.has(authInsecureOption)) {

                final SSLContext ctx = SSLContext.getInstance("TLS");
                final X509TrustManager tm = new InsecureX509TrustManager();
                ctx.init(null, new TrustManager[] { tm }, null);

                final HostnameVerifier v = new HostnameVerifier() {

                    @Override
                    public boolean verify(String s, SSLSession sslSession) {
                        return true;
                    }
                };

                final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(ctx, v);

                final CloseableHttpClient httpClient = CachingHttpClientBuilder
                        .create()
                        // allow caching
                        .setCacheConfig(cacheConfig)
                        // Wrap the local JarCacheStorage around a BasicHttpCacheStorage
                        .setHttpCacheStorage(
                                new JarCacheStorage(null, cacheConfig, new BasicHttpCacheStorage(
                                        cacheConfig)))

                        // Add in the credentials provider
                        .setDefaultCredentialsProvider(credsProvider)

                        // insecure ssl connections
                        .setSSLSocketFactory(sslsf)

                        // When you are finished setting the properties, call build
                        .build();
                documentLoader.setHttpClient(httpClient);
                opts.setDocumentLoader(documentLoader);

            } else {

                final CloseableHttpClient httpClient = CachingHttpClientBuilder
                        .create()
                        // allow caching
                        .setCacheConfig(cacheConfig)
                        // Wrap the local JarCacheStorage around a BasicHttpCacheStorage
                        .setHttpCacheStorage(
                                new JarCacheStorage(null, cacheConfig, new BasicHttpCacheStorage(
                                        cacheConfig)))

                        // Add in the credentials provider
                        .setDefaultCredentialsProvider(credsProvider)

                        // When you are finished setting the properties, call build
                        .build();

                documentLoader.setHttpClient(httpClient);
                opts.setDocumentLoader(documentLoader);

            }
        }

        if ("fromrdf".equals(processingOptionValue)) {
            inobj = readFile(options.valueOf(inputFile));
        } else {
            inobj = JsonUtils.fromInputStream(new FileInputStream(options.valueOf(inputFile)));
        }

        if (hasContext(processingOptionValue) && options.has(context)) {
            if (!options.valueOf(context).exists()) {
                System.out.println(
                        "Error: context file \"" + options.valueOf(context) + "\" doesn't exist");
                parser.printHelpOn(System.out);
                return;
            }
            ctxobj = JsonUtils.fromInputStream(new FileInputStream(options.valueOf(context)));
        }

        Object outobj = null;
        if ("fromrdf".equals(processingOptionValue)) {
            final Model inModel = Rio.parse(new StringReader((String) inobj), opts.getBase(),
                    sesameInputFormat);

            outobj = JsonLdProcessor.fromRDF(inModel, opts, new RDF4JJSONLDRDFParser());
        } else if ("tordf".equals(processingOptionValue)) {
            opts.useNamespaces = true;
            outobj = JsonLdProcessor.toRDF(inobj,
                    new RDF4JJSONLDTripleCallback(Rio.createWriter(sesameOutputFormat, System.out)),
                    opts);
        } else if ("expand".equals(processingOptionValue)) {
            outobj = JsonLdProcessor.expand(inobj, opts);
        } else if ("compact".equals(processingOptionValue)) {
            if (ctxobj == null) {
                System.out.println("Error: The compaction context must not be null.");
                parser.printHelpOn(System.out);
                return;
            }
            outobj = JsonLdProcessor.compact(inobj, ctxobj, opts);
        } else if ("normalize".equals(processingOptionValue)) {
            // see https://github.com/jsonld-java/jsonld-java/issues/193
            // outobj = JsonLdProcessor.normalize(inobj, opts);

            // see https://github.com/jsonld-java/jsonld-java/issues/194
            // until this is fixed, it is necessary to clear the format so that JsonLdProcessor won't try to interpret it.
            opts.format = null;

            // If an output format is specified, add a callback to show the result.
            Object result = JsonLdProcessor.toRDF(
                    inobj,
                    options.has(outputFormat)
                            ? new RDF4JJSONLDTripleCallback(Rio.createWriter(sesameOutputFormat, System.out))
                            : null,
                    opts);
            if (RDFDataset.class.isInstance(result)) {
                RDFDataset rdfds = RDFDataset.class.cast(result);
                outobj = new JsonLdApi(opts).normalize(rdfds);
            } else {
                outobj = result;
            }
        } else if ("frame".equals(processingOptionValue)) {
            if (ctxobj != null && !(ctxobj instanceof Map)) {
                System.out.println(
                        "Invalid JSON-LD syntax; a JSON-LD frame must be a single object.");
                parser.printHelpOn(System.out);
                return;
            }
            outobj = JsonLdProcessor.frame(inobj, ctxobj, opts);
        } else if ("flatten".equals(processingOptionValue)) {
            outobj = JsonLdProcessor.flatten(inobj, ctxobj, opts);
        } else {
            System.out
                    .println("Error: invalid processing option \"" + processingOptionValue + "\"");
            parser.printHelpOn(System.out);
            return;
        }

        if ("tordf".equals(processingOptionValue)) {
            // Already serialised above
        } else if ("normalize".equals(processingOptionValue)) {
            if (!options.has(outputFormat)) {
                // if no output format was specified, then show the result.
                System.out.println(JsonUtils.toPrettyString(outobj));
            }
        } else {
            System.out.println(JsonUtils.toPrettyString(outobj));
        }
    }

    private static Set<String> getProcessingOptions() {
        return new LinkedHashSet<String>(Arrays.asList("expand", "compact", "frame", "normalize",
                "flatten", "fromrdf", "tordf"));
    }

    private static boolean hasContext(String opt) {
        return "compact".equals(opt) || "frame".equals(opt) || "flatten".equals(opt);
    }

    private static Map<String, RDFFormat> getOutputFormats() {
        final Map<String, RDFFormat> outputFormats = new HashMap<String, RDFFormat>();

        for (final RDFFormat format : RDFParserRegistry.getInstance().getKeys()) {
            outputFormats.put(
                    format.getName().replaceAll("-", "").replaceAll("/", "").toLowerCase(), format);
        }

        return outputFormats;
    }

    private static String readFile(File in) throws IOException {
        String inobj = "";
        try (BufferedReader buf = Files.newBufferedReader(in.toPath(), StandardCharsets.UTF_8)){
            String line;
            while ((line = buf.readLine()) != null) {
                line = line.trim();
                inobj = (inobj) + line + "\n";
            }
        }
        return inobj;
    }

    private static class InsecureX509TrustManager extends X509ExtendedTrustManager implements X509TrustManager {

        public void checkClientTrusted(X509Certificate[] xcs, String string) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
        }

        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return null;
        }


        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
        }
    }

}
