<?xml version="1.0" ?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:wix="http://schemas.microsoft.com/wix/2006/wi">

    <!-- Copy all attributes and elements to the output. -->
    <xsl:template match="@*|*">
        <xsl:copy>
            <xsl:apply-templates select="@*" />
            <xsl:apply-templates select="*" />
        </xsl:copy>
    </xsl:template>

    <xsl:output method="xml" indent="yes" />

    <!-- Create searches for the directories to remove. -->
    <xsl:key name="git-search" match="wix:Directory[@Name = '.git']" use="@Id" />
    <xsl:key name="installer-search" match="wix:Directory[@Name = 'installer']" use="@Id" />

    <xsl:key name="git-comp-ref" match="wix:Component[key('git-search', @Directory)]" use="@Id" />
    <xsl:key name="ist-comp-ref" match="wix:Component[key('installer-search', @Directory)]" use="@Id" />
    <xsl:template match="wix:ComponentRef[key('git-comp-ref', @Id)]" />
    <xsl:template match="wix:ComponentRef[key('ist-comp-ref', @Id)]" />

    <!-- Remove directories. -->
    <xsl:template match="wix:Directory[@Name='.git']" />
    <xsl:template match="wix:Directory[@Name='installer']" />

    <!-- Remove Components referencing those directories. -->
    <xsl:template match="wix:Component[key('git-search', @Directory)]" />
    <xsl:template match="wix:Component[key('installer-search', @Directory)]" />

    <!-- Remove DirectoryRefs (and their parent Fragments) referencing those directories. -->
    <xsl:template match="wix:Fragment[wix:DirectoryRef[key('git-search', @Id)]]" />
    <xsl:template match="wix:Fragment[wix:DirectoryRef[key('installer-search', @Id)]]" />
</xsl:stylesheet>