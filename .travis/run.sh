
case "${TOXENV}" in
    lint)
        pyflakes vertex bin prime
        pip install diff_cover
        bash .travis/twistedchecker-trunk-diff.sh vertex
        ;;
    py27)
        coverage run `which trial` vertex
        ;;
esac;
