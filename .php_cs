<?php

$finder = Symfony\Component\Finder\Finder::create()
    ->notPath('vendor')
    ->in(__DIR__)
    ->name('*.php');

return PhpCsFixer\Config::create()
    ->setRules([
        '@PSR2' => true,
        'array_syntax' => ['syntax' => 'short'],
        'ordered_imports' => ['sortAlgorithm' => 'alpha'],
        'no_unused_imports' => true,
        'no_unreachable_default_argument_value' => false,
        'braces' => ['allow_single_line_closure' => true],
        'heredoc_to_nowdoc' => false,
        'phpdoc_annotation_without_dot' => false,
        'ternary_to_null_coalescing' => false,
    ])
    ->setRiskyAllowed(false)
    ->setFinder($finder);