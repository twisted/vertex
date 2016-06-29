
case "${TOXENV}" in
    lint)
        pyflakes vertex bin prime
        rm -fr .baseline
        mkdir .baseline
        (
            cd .baseline
            git --work-tree . checkout origin/master .
            twistedchecker vertex > ../.baseline.result
        )
        twistedchecker --diff=.baseline.result vertex
        ;;
    py27)
        coverage run `which trial` vertex
        ;;
esac;
